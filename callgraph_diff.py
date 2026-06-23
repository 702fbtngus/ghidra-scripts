#!/usr/bin/env python3

import argparse
import csv
import html
import re
from collections import defaultdict, deque
from pathlib import Path


NODE_RE = re.compile(r'^\s*"((?:\\.|[^"\\])*)"\s+\[(.*)\];\s*$')
EDGE_RE = re.compile(r'^\s*"((?:\\.|[^"\\])*)"\s*->\s*"((?:\\.|[^"\\])*)"(?:\s+\[(.*)\])?;\s*$')
ATTR_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"\\])*)"')

COMMON_EDGE_COLOR = "#9ca3af"
EMUL_ONLY_EDGE_COLOR = "#f97316"
BASELINE_ONLY_EDGE_COLOR = "#cbd5e1"


def unescape_dot(value):
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def quote_dot(value):
    return '"' + value.replace("\\", r"\\").replace('"', r"\"") + '"'


def parse_attrs(raw_attrs):
    attrs = {}
    if raw_attrs is None:
        return attrs
    for key, value in ATTR_RE.findall(raw_attrs):
        attrs[key] = unescape_dot(value)
    return attrs


def parse_callgraph_dot(path):
    nodes = {}
    edges = set()

    with Path(path).open(encoding="utf-8") as dot_file:
        for line in dot_file:
            edge_match = EDGE_RE.match(line)
            if edge_match:
                source = unescape_dot(edge_match.group(1))
                target = unescape_dot(edge_match.group(2))
                edges.add((source, target))
                continue

            node_match = NODE_RE.match(line)
            if node_match:
                node_id = unescape_dot(node_match.group(1))
                attrs = parse_attrs(node_match.group(2))
                nodes[node_id] = {
                    "label": attrs.get("label", node_id),
                    "shape": attrs.get("shape", "box"),
                    "fillcolor": attrs.get("fillcolor", "#f8fafc"),
                }

    for source, target in edges:
        nodes.setdefault(source, {"label": source, "shape": "box", "fillcolor": "#f8fafc"})
        nodes.setdefault(target, {"label": target, "shape": "box", "fillcolor": "#f8fafc"})

    return nodes, edges


def strongly_connected_components(nodes, edges):
    adjacency = {node: [] for node in nodes}
    for source, target in edges:
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])

    index = 0
    stack = []
    on_stack = set()
    indices = {}
    lowlinks = {}
    components = []

    def visit(node):
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for target in adjacency.get(node, []):
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(sorted(component))

    for node in sorted(nodes):
        if node not in indices:
            visit(node)

    return components


def compute_layout(nodes, edges):
    components = strongly_connected_components(nodes, edges)
    component_by_node = {}
    for component_id, component in enumerate(components):
        for node in component:
            component_by_node[node] = component_id

    component_edges = defaultdict(set)
    indegree = [0] * len(components)
    for source, target in edges:
        source_component = component_by_node[source]
        target_component = component_by_node[target]
        if source_component == target_component:
            continue
        if target_component not in component_edges[source_component]:
            component_edges[source_component].add(target_component)
            indegree[target_component] += 1

    ranks = [0] * len(components)
    queue = deque(sorted(i for i, degree in enumerate(indegree) if degree == 0))
    remaining_indegree = list(indegree)
    while queue:
        component_id = queue.popleft()
        for target_component in sorted(component_edges[component_id]):
            ranks[target_component] = max(ranks[target_component], ranks[component_id] + 1)
            remaining_indegree[target_component] -= 1
            if remaining_indegree[target_component] == 0:
                queue.append(target_component)

    rank_groups = defaultdict(list)
    for component_id, component in enumerate(components):
        rank_groups[ranks[component_id]].extend(component)

    node_width = 190
    node_height = 22
    x_gap = 270
    y_gap = 34
    margin_x = 60
    margin_top = 125
    legend_height = 80

    positions = {}
    for rank in sorted(rank_groups):
        for row, node_id in enumerate(sorted(rank_groups[rank])):
            positions[node_id] = (
                margin_x + rank * x_gap,
                margin_top + legend_height + row * y_gap,
            )

    max_rank = max(rank_groups.keys(), default=0)
    max_rows = max((len(group) for group in rank_groups.values()), default=1)
    width = margin_x * 2 + max_rank * x_gap + node_width + 80
    height = margin_top + legend_height + max_rows * y_gap + 80

    return positions, width, height, node_width, node_height


def write_diff_dot(path, nodes, common_edges, emul_only_edges, baseline_only_edges):
    with Path(path).open("w", encoding="utf-8") as dot_file:
        dot_file.write("digraph callgraph_diff {\n")
        dot_file.write("  rankdir=LR;\n")
        dot_file.write("  graph [splines=true, overlap=false];\n")
        dot_file.write('  node [style=filled, shape=box, fontname="Helvetica"];\n')
        dot_file.write('  edge [fontname="Helvetica"];\n')

        for node_id in sorted(nodes):
            node = nodes[node_id]
            dot_file.write(
                f"  {quote_dot(node_id)} [label={quote_dot(node['label'])}, "
                'fillcolor="#f8fafc", color="#cbd5e1", shape="box"];\n'
            )

        for source, target in sorted(common_edges):
            dot_file.write(
                f"  {quote_dot(source)} -> {quote_dot(target)} "
                f'[color="{COMMON_EDGE_COLOR}", penwidth="1.0"];\n'
            )

        for source, target in sorted(baseline_only_edges):
            dot_file.write(
                f"  {quote_dot(source)} -> {quote_dot(target)} "
                f'[color="{BASELINE_ONLY_EDGE_COLOR}", style="dashed", penwidth="1.2"];\n'
            )

        for source, target in sorted(emul_only_edges):
            dot_file.write(
                f"  {quote_dot(source)} -> {quote_dot(target)} "
                f'[color="{EMUL_ONLY_EDGE_COLOR}", penwidth="2.8"];\n'
            )

        dot_file.write("}\n")


def edge_path(source_pos, target_pos, node_width, node_height):
    source_x, source_y = source_pos
    target_x, target_y = target_pos
    x1 = source_x + node_width
    y1 = source_y + node_height / 2
    x2 = target_x
    y2 = target_y + node_height / 2
    control_dx = max(60, abs(x2 - x1) / 2)
    return f"M {x1:.1f} {y1:.1f} C {x1 + control_dx:.1f} {y1:.1f}, {x2 - control_dx:.1f} {y2:.1f}, {x2:.1f} {y2:.1f}"


def display_label(label, max_chars=28):
    if len(label) <= max_chars:
        return label
    return label[: max_chars - 3] + "..."


def write_svg(path, nodes, common_edges, emul_only_edges, baseline_only_edges):
    union_edges = common_edges | emul_only_edges | baseline_only_edges
    positions, width, height, node_width, node_height = compute_layout(nodes, union_edges)
    highlighted_nodes = {node for edge in emul_only_edges for node in edge}

    with Path(path).open("w", encoding="utf-8") as svg_file:
        svg_file.write(
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">\n'
        )
        svg_file.write("<defs>\n")
        svg_file.write(
            f'<marker id="arrow-common" markerWidth="8" markerHeight="8" refX="7" refY="3.5" '
            f'orient="auto" markerUnits="strokeWidth"><path d="M0,0 L7,3.5 L0,7 Z" fill="{COMMON_EDGE_COLOR}"/></marker>\n'
        )
        svg_file.write(
            f'<marker id="arrow-emul" markerWidth="9" markerHeight="9" refX="8" refY="4" '
            f'orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,4 L0,8 Z" fill="{EMUL_ONLY_EDGE_COLOR}"/></marker>\n'
        )
        svg_file.write("</defs>\n")
        svg_file.write('<rect width="100%" height="100%" fill="#ffffff"/>\n')
        svg_file.write('<text x="60" y="44" font-family="Helvetica, Arial, sans-serif" font-size="22" fill="#111827">Static call graph diff</text>\n')
        svg_file.write(
            f'<text x="60" y="72" font-family="Helvetica, Arial, sans-serif" font-size="13" fill="#4b5563">'
            f'common={len(common_edges)}  emul-only={len(emul_only_edges)}  no-emul-only={len(baseline_only_edges)}'
            "</text>\n"
        )
        write_legend(svg_file, 60, 98)

        for source, target in sorted(common_edges):
            svg_file.write(
                f'<path d="{edge_path(positions[source], positions[target], node_width, node_height)}" '
                f'fill="none" stroke="{COMMON_EDGE_COLOR}" stroke-width="1.0" stroke-opacity="0.24" marker-end="url(#arrow-common)"/>\n'
            )

        for source, target in sorted(baseline_only_edges):
            svg_file.write(
                f'<path d="{edge_path(positions[source], positions[target], node_width, node_height)}" '
                f'fill="none" stroke="{BASELINE_ONLY_EDGE_COLOR}" stroke-width="1.2" stroke-opacity="0.45" '
                'stroke-dasharray="5 4" marker-end="url(#arrow-common)"/>\n'
            )

        for source, target in sorted(emul_only_edges):
            svg_file.write(
                f'<path d="{edge_path(positions[source], positions[target], node_width, node_height)}" '
                f'fill="none" stroke="{EMUL_ONLY_EDGE_COLOR}" stroke-width="2.8" stroke-opacity="0.95" marker-end="url(#arrow-emul)"/>\n'
            )

        for node_id in sorted(nodes):
            x, y = positions[node_id]
            node = nodes[node_id]
            fill = "#fff7ed" if node_id in highlighted_nodes else "#f8fafc"
            stroke = "#fb923c" if node_id in highlighted_nodes else "#cbd5e1"
            full_label = node["label"]
            label = html.escape(display_label(full_label))
            title = html.escape(f"{full_label} @ {node_id}")
            svg_file.write("<g>\n")
            svg_file.write(f"<title>{title}</title>\n")
            svg_file.write(
                f'<rect x="{x}" y="{y}" width="{node_width}" height="{node_height}" rx="3" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="1"/>\n'
            )
            svg_file.write(
                f'<text x="{x + 6}" y="{y + 15}" font-family="Helvetica, Arial, sans-serif" '
                f'font-size="10" fill="#111827">{label}</text>\n'
            )
            svg_file.write("</g>\n")

        svg_file.write("</svg>\n")


def write_legend(svg_file, x, y):
    items = [
        ("both graphs", COMMON_EDGE_COLOR, "1.8", None),
        ("emul only", EMUL_ONLY_EDGE_COLOR, "3.0", None),
        ("no-emul only", BASELINE_ONLY_EDGE_COLOR, "2.0", "5 4"),
    ]
    cursor_x = x
    for label, color, stroke_width, dasharray in items:
        dash = f' stroke-dasharray="{dasharray}"' if dasharray else ""
        svg_file.write(
            f'<line x1="{cursor_x}" y1="{y}" x2="{cursor_x + 38}" y2="{y}" '
            f'stroke="{color}" stroke-width="{stroke_width}"{dash}/>\n'
        )
        svg_file.write(
            f'<text x="{cursor_x + 46}" y="{y + 4}" font-family="Helvetica, Arial, sans-serif" '
            f'font-size="12" fill="#374151">{html.escape(label)}</text>\n'
        )
        cursor_x += 150


def parse_indirect_flow_sites(path):
    sites = []
    path = Path(path)
    if not path.exists():
        return sites

    with path.open(encoding="utf-8", newline="") as sites_file:
        reader = csv.DictReader(sites_file, delimiter="\t")
        for row in reader:
            row["covered_by_emulation"] = (
                row.get("covered_by_emulation", "").strip().lower() == "true"
            )
            row["excluded"] = row.get("excluded", "").strip().lower() == "true"
            sites.append(row)
    return sites


def compute_indirect_flow_coverage(baseline_sites_path, emul_sites_path):
    if baseline_sites_path is None or emul_sites_path is None:
        return None

    all_baseline_sites = parse_indirect_flow_sites(baseline_sites_path)
    baseline_sites = [site for site in all_baseline_sites if not site.get("excluded")]
    emul_sites_by_address = {
        site.get("address"): site
        for site in parse_indirect_flow_sites(emul_sites_path)
    }

    covered = []
    uncovered = []
    for site in baseline_sites:
        emul_site = emul_sites_by_address.get(site.get("address"))
        merged_site = dict(site)
        if emul_site:
            merged_site["emul_targets"] = emul_site.get("targets", "")
        else:
            merged_site["emul_targets"] = ""

        if emul_site and emul_site.get("covered_by_emulation"):
            covered.append(merged_site)
        else:
            uncovered.append(merged_site)

    excluded = []
    for site in all_baseline_sites:
        if not site.get("excluded"):
            continue
        emul_site = emul_sites_by_address.get(site.get("address"))
        merged_site = dict(site)
        if emul_site:
            merged_site["emul_targets"] = emul_site.get("targets", "")
            merged_site["covered_by_emulation"] = emul_site.get("covered_by_emulation", False)
        else:
            merged_site["emul_targets"] = ""
        excluded.append(merged_site)

    def count_kind(sites, kind):
        return sum(1 for site in sites if site.get("kind") == kind)

    total = len(baseline_sites)
    covered_count = len(covered)
    return {
        "baseline_total": len(all_baseline_sites),
        "total": total,
        "calls_total": count_kind(baseline_sites, "call"),
        "jumps_total": count_kind(baseline_sites, "jump"),
        "covered": covered_count,
        "covered_calls": count_kind(covered, "call"),
        "covered_jumps": count_kind(covered, "jump"),
        "uncovered": total - covered_count,
        "excluded": len(excluded),
        "excluded_calls": count_kind(excluded, "call"),
        "excluded_jumps": count_kind(excluded, "jump"),
        "coverage_percent": 0.0 if total == 0 else (covered_count * 100.0) / total,
        "covered_sites": covered,
        "uncovered_sites": uncovered,
        "excluded_sites": excluded,
    }


def write_indirect_coverage_section(summary_file, indirect_coverage):
    if indirect_coverage is None:
        return

    summary_file.write("\n[indirect_flow_coverage]\n")
    summary_file.write(f"baseline_indirect_sites_total={indirect_coverage['baseline_total']}\n")
    summary_file.write(f"baseline_indirect_sites={indirect_coverage['total']}\n")
    summary_file.write(f"baseline_indirect_calls={indirect_coverage['calls_total']}\n")
    summary_file.write(f"baseline_indirect_jumps={indirect_coverage['jumps_total']}\n")
    summary_file.write(f"covered_by_emulation={indirect_coverage['covered']}\n")
    summary_file.write(f"covered_calls_by_emulation={indirect_coverage['covered_calls']}\n")
    summary_file.write(f"covered_jumps_by_emulation={indirect_coverage['covered_jumps']}\n")
    summary_file.write(f"uncovered_by_emulation={indirect_coverage['uncovered']}\n")
    summary_file.write(f"excluded_indirect_sites={indirect_coverage['excluded']}\n")
    summary_file.write(f"excluded_indirect_calls={indirect_coverage['excluded_calls']}\n")
    summary_file.write(f"excluded_indirect_jumps={indirect_coverage['excluded_jumps']}\n")
    summary_file.write(f"coverage_percent={indirect_coverage['coverage_percent']:.1f}\n")

    if indirect_coverage["covered_sites"]:
        summary_file.write("\n[covered_indirect_sites]\n")
        for site in indirect_coverage["covered_sites"]:
            summary_file.write(
                f"{site.get('address')} {site.get('kind')} {site.get('mnemonic')} "
                f"{site.get('function')} targets={site.get('emul_targets', '')}\n"
            )

    if indirect_coverage["uncovered_sites"]:
        summary_file.write("\n[uncovered_indirect_sites]\n")
        for site in indirect_coverage["uncovered_sites"]:
            summary_file.write(
                f"{site.get('address')} {site.get('kind')} {site.get('mnemonic')} "
                f"{site.get('function')}\n"
            )

    if indirect_coverage["excluded_sites"]:
        summary_file.write("\n[excluded_indirect_sites]\n")
        for site in indirect_coverage["excluded_sites"]:
            summary_file.write(
                f"{site.get('address')} {site.get('kind')} {site.get('mnemonic')} "
                f"{site.get('function')} covered={str(site.get('covered_by_emulation', False)).lower()} "
                f"targets={site.get('emul_targets') or site.get('targets', '')}\n"
            )


def write_summary(path, common_edges, emul_only_edges, baseline_only_edges, indirect_coverage=None):
    with Path(path).open("w", encoding="utf-8") as summary_file:
        summary_file.write(f"common_edges={len(common_edges)}\n")
        summary_file.write(f"emul_only_edges={len(emul_only_edges)}\n")
        summary_file.write(f"no_emul_only_edges={len(baseline_only_edges)}\n")
        write_indirect_coverage_section(summary_file, indirect_coverage)
        if emul_only_edges:
            summary_file.write("\n[emul_only]\n")
            for source, target in sorted(emul_only_edges):
                summary_file.write(f"{source} -> {target}\n")
        if baseline_only_edges:
            summary_file.write("\n[no_emul_only]\n")
            for source, target in sorted(baseline_only_edges):
                summary_file.write(f"{source} -> {target}\n")


def build_callgraph_diff(
    baseline_dot,
    emul_dot,
    output_dir,
    baseline_indirect_sites=None,
    emul_indirect_sites=None,
):
    baseline_nodes, baseline_edges = parse_callgraph_dot(baseline_dot)
    emul_nodes, emul_edges = parse_callgraph_dot(emul_dot)
    nodes = {**baseline_nodes, **emul_nodes}

    common_edges = baseline_edges & emul_edges
    emul_only_edges = emul_edges - baseline_edges
    baseline_only_edges = baseline_edges - emul_edges

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dot_path = output_dir / "callgraph_static_diff.dot"
    svg_path = output_dir / "callgraph_static_diff.svg"
    summary_path = output_dir / "callgraph_static_diff_summary.txt"

    indirect_coverage = compute_indirect_flow_coverage(
        baseline_indirect_sites,
        emul_indirect_sites,
    )

    write_diff_dot(dot_path, nodes, common_edges, emul_only_edges, baseline_only_edges)
    write_svg(svg_path, nodes, common_edges, emul_only_edges, baseline_only_edges)
    write_summary(
        summary_path,
        common_edges,
        emul_only_edges,
        baseline_only_edges,
        indirect_coverage,
    )

    result = {
        "dot": dot_path,
        "svg": svg_path,
        "summary": summary_path,
        "common_edges": len(common_edges),
        "emul_only_edges": len(emul_only_edges),
        "no_emul_only_edges": len(baseline_only_edges),
    }
    if indirect_coverage is not None:
        result.update({
            "indirect_sites": indirect_coverage["total"],
            "indirect_covered": indirect_coverage["covered"],
            "indirect_excluded": indirect_coverage["excluded"],
            "indirect_coverage_percent": indirect_coverage["coverage_percent"],
        })
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline_dot")
    parser.add_argument("emul_dot")
    parser.add_argument("output_dir")
    parser.add_argument("--baseline-indirect-sites")
    parser.add_argument("--emul-indirect-sites")
    args = parser.parse_args()
    result = build_callgraph_diff(
        args.baseline_dot,
        args.emul_dot,
        args.output_dir,
        args.baseline_indirect_sites,
        args.emul_indirect_sites,
    )
    print(f"Diff DOT: {result['dot']}")
    print(f"Diff SVG: {result['svg']}")
    print(f"Diff summary: {result['summary']}")
    print(
        "Edges: "
        f"common={result['common_edges']} "
        f"emul-only={result['emul_only_edges']} "
        f"no-emul-only={result['no_emul_only_edges']}"
    )
    if "indirect_sites" in result:
        print(
            "Indirect coverage: "
            f"covered={result['indirect_covered']}/{result['indirect_sites']} "
            f"({result['indirect_coverage_percent']:.1f}%), "
            f"excluded={result['indirect_excluded']}"
        )


if __name__ == "__main__":
    main()
