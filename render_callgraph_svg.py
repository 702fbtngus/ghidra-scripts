#!/usr/bin/env python3

from __future__ import annotations

import argparse
import html
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path


NODE_RE = re.compile(
    r'^\s*"(?P<id>(?:[^"\\]|\\.)*)"\s+\[label="(?P<label>(?:[^"\\]|\\.)*)", '
    r'fillcolor="(?P<fillcolor>#[0-9a-fA-F]{6})", shape="(?P<shape>[^"]+)"\];\s*$'
)
EDGE_RE = re.compile(
    r'^\s*"(?P<src>(?:[^"\\]|\\.)*)"\s+->\s+"(?P<dst>(?:[^"\\]|\\.)*)"'
    r'(?:\s+\[[^\]]*\])?;\s*$'
)


@dataclass(frozen=True)
class Node:
    node_id: str
    label: str
    fillcolor: str
    shape: str


def unescape_dot(value: str) -> str:
    return value.replace(r"\\", "\\").replace(r"\"", '"')


def parse_dot(dot_path: Path) -> tuple[dict[str, Node], list[tuple[str, str]]]:
    nodes: dict[str, Node] = {}
    edges: list[tuple[str, str]] = []

    for raw_line in dot_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line in {"digraph callgraph {", "}"}:
            continue
        if line.startswith(("rankdir=", "graph ", "node ", "edge ")):
            continue

        node_match = NODE_RE.match(line)
        if node_match:
            node_id = unescape_dot(node_match.group("id"))
            nodes[node_id] = Node(
                node_id=node_id,
                label=unescape_dot(node_match.group("label")),
                fillcolor=node_match.group("fillcolor"),
                shape=node_match.group("shape"),
            )
            continue

        edge_match = EDGE_RE.match(line)
        if edge_match:
            edges.append((
                unescape_dot(edge_match.group("src")),
                unescape_dot(edge_match.group("dst")),
            ))
            continue

    return nodes, edges


def tarjan_scc(nodes: dict[str, Node], edges: list[tuple[str, str]]) -> list[list[str]]:
    adjacency: dict[str, list[str]] = defaultdict(list)
    for src, dst in edges:
        if src in nodes and dst in nodes:
            adjacency[src].append(dst)

    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def strongconnect(node_id: str) -> None:
        nonlocal index
        indices[node_id] = index
        lowlink[node_id] = index
        index += 1
        stack.append(node_id)
        on_stack.add(node_id)

        for neighbor in adjacency[node_id]:
            if neighbor not in indices:
                strongconnect(neighbor)
                lowlink[node_id] = min(lowlink[node_id], lowlink[neighbor])
            elif neighbor in on_stack:
                lowlink[node_id] = min(lowlink[node_id], indices[neighbor])

        if lowlink[node_id] == indices[node_id]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node_id:
                    break
            components.append(component)

    for node_id in nodes:
        if node_id not in indices:
            strongconnect(node_id)

    return components


def assign_layers(nodes: dict[str, Node], edges: list[tuple[str, str]]) -> tuple[dict[str, int], list[list[str]]]:
    components = tarjan_scc(nodes, edges)
    component_of: dict[str, int] = {}
    for idx, component in enumerate(components):
        for node_id in component:
            component_of[node_id] = idx

    dag_successors: dict[int, set[int]] = defaultdict(set)
    dag_indegree: dict[int, int] = {idx: 0 for idx in range(len(components))}

    for src, dst in edges:
        src_component = component_of[src]
        dst_component = component_of[dst]
        if src_component == dst_component:
            continue
        if dst_component not in dag_successors[src_component]:
            dag_successors[src_component].add(dst_component)
            dag_indegree[dst_component] += 1

    queue = deque(sorted(
        (idx for idx, indegree in dag_indegree.items() if indegree == 0),
        key=lambda idx: min(components[idx]),
    ))
    topo_order: list[int] = []
    while queue:
        component_idx = queue.popleft()
        topo_order.append(component_idx)
        for successor in sorted(dag_successors[component_idx]):
            dag_indegree[successor] -= 1
            if dag_indegree[successor] == 0:
                queue.append(successor)

    component_layer: dict[int, int] = {idx: 0 for idx in range(len(components))}
    for component_idx in topo_order:
        for successor in dag_successors[component_idx]:
            component_layer[successor] = max(
                component_layer[successor],
                component_layer[component_idx] + 1,
            )

    layers: dict[int, list[str]] = defaultdict(list)
    for component_idx, component in enumerate(components):
        ordered_component = sorted(component, key=lambda node_id: (nodes[node_id].label, node_id))
        layers[component_layer[component_idx]].extend(ordered_component)

    ordered_layers = [layers[index] for index in sorted(layers)]
    node_layer = {
        node_id: layer_idx
        for layer_idx, layer_nodes in enumerate(ordered_layers)
        for node_id in layer_nodes
    }
    return node_layer, ordered_layers


def build_svg(nodes: dict[str, Node], edges: list[tuple[str, str]]) -> str:
    if not nodes:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="120">'
            '<text x="20" y="60" font-family="monospace" font-size="20">'
            "No nodes found in DOT file"
            "</text></svg>"
        )

    node_layer, ordered_layers = assign_layers(nodes, edges)

    layer_gap = 280
    row_gap = 48
    margin_x = 80
    margin_y = 80
    box_width = 190
    box_height = 28
    max_layer_size = max(len(layer) for layer in ordered_layers)
    width = margin_x * 2 + max(1, len(ordered_layers) - 1) * layer_gap + box_width
    height = margin_y * 2 + max(1, max_layer_size - 1) * row_gap + box_height

    positions: dict[str, tuple[float, float]] = {}
    for layer_idx, layer_nodes in enumerate(ordered_layers):
        total_height = (len(layer_nodes) - 1) * row_gap
        y_start = margin_y + (height - 2 * margin_y - total_height - box_height) / 2
        x = margin_x + layer_idx * layer_gap
        for row_idx, node_id in enumerate(layer_nodes):
            y = y_start + row_idx * row_gap
            positions[node_id] = (x, y)

    outgoing_count: dict[str, int] = defaultdict(int)
    for src, _dst in edges:
        outgoing_count[src] += 1

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<style>",
        "text { font-family: Helvetica, Arial, sans-serif; }",
        ".label { font-size: 11px; fill: #1f2933; }",
        ".small { font-size: 9px; fill: #52606d; }",
        ".edge { stroke: #94a3b8; stroke-width: 1; fill: none; stroke-opacity: 0.35; }",
        ".edge-intra { stroke: #64748b; stroke-dasharray: 2 3; stroke-opacity: 0.20; }",
        ".node { stroke: #475569; stroke-width: 1; }",
        "</style>",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f8fafc" />',
        '<text x="24" y="32" font-size="20" font-weight="700">Call Graph</text>',
        f'<text x="24" y="52" class="small">nodes={len(nodes)} edges={len(edges)} layers={len(ordered_layers)}</text>',
    ]

    for src, dst in edges:
        if src not in positions or dst not in positions:
            continue
        x1, y1 = positions[src]
        x2, y2 = positions[dst]
        start_x = x1 + box_width
        start_y = y1 + box_height / 2
        end_x = x2
        end_y = y2 + box_height / 2
        mid_x = (start_x + end_x) / 2
        css_class = "edge-intra" if node_layer[src] == node_layer[dst] else "edge"
        svg.append(
            f'<path class="{css_class}" d="M {start_x:.1f} {start_y:.1f} '
            f'C {mid_x:.1f} {start_y:.1f}, {mid_x:.1f} {end_y:.1f}, {end_x:.1f} {end_y:.1f}" />'
        )

    for node_id, node in sorted(nodes.items(), key=lambda item: (node_layer[item[0]], item[1].label, item[0])):
        x, y = positions[node_id]
        escaped_label = html.escape(node.label)
        escaped_id = html.escape(node_id)
        count_text = html.escape(str(outgoing_count[node_id]))

        if node.shape == "ellipse":
            cx = x + box_width / 2
            cy = y + box_height / 2
            svg.append(
                f'<ellipse class="node" cx="{cx:.1f}" cy="{cy:.1f}" rx="{box_width / 2:.1f}" '
                f'ry="{box_height / 2:.1f}" fill="{node.fillcolor}" />'
            )
        else:
            svg.append(
                f'<rect class="node" x="{x:.1f}" y="{y:.1f}" width="{box_width}" height="{box_height}" '
                f'rx="6" ry="6" fill="{node.fillcolor}" />'
            )

        svg.append(f'<title>{escaped_label} ({escaped_id})</title>')
        svg.append(f'<text class="label" x="{x + 8:.1f}" y="{y + 17:.1f}">{escaped_label}</text>')
        svg.append(
            f'<text class="small" x="{x + box_width - 42:.1f}" y="{y + 18:.1f}">out:{count_text}</text>'
        )

    svg.append("</svg>")
    return "\n".join(svg)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render CallGraphBuilder DOT output as SVG.")
    parser.add_argument("dot_file", nargs="?", default="cg/callgraph.dot")
    parser.add_argument("svg_file", nargs="?", default="cg/callgraph.svg")
    args = parser.parse_args()

    dot_path = Path(args.dot_file)
    svg_path = Path(args.svg_file)

    nodes, edges = parse_dot(dot_path)
    svg_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.write_text(build_svg(nodes, edges))

    print(f"Wrote {svg_path} with {len(nodes)} nodes and {len(edges)} edges.")


if __name__ == "__main__":
    main()
