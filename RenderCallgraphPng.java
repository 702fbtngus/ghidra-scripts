import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.geom.CubicCurve2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;

public class RenderCallgraphPng {

    private static final Pattern NODE_PATTERN = Pattern.compile(
        "^\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s+\\[label=\"((?:[^\"\\\\]|\\\\.)*)\", " +
        "fillcolor=\"(#[0-9a-fA-F]{6})\", shape=\"([^\"]+)\"\\];\\s*$"
    );
    private static final Pattern EDGE_PATTERN = Pattern.compile(
        "^\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\s+->\\s+\"((?:[^\"\\\\]|\\\\.)*)\"" +
        "(?:\\s+\\[[^\\]]*\\])?;\\s*$"
    );

    private static final int HEADER_HEIGHT = 60;
    private static final int MARGIN_X = 60;
    private static final int MARGIN_Y = 40;
    private static final int LAYER_GAP = 160;
    private static final int ROW_GAP = 18;
    private static final int BOX_WIDTH = 130;
    private static final int BOX_HEIGHT = 18;
    private static final Color BACKGROUND_COLOR = new Color(0xf8, 0xfa, 0xfc);
    private static final Color TITLE_COLOR = new Color(0x1f, 0x29, 0x33);
    private static final Color META_COLOR = new Color(0x52, 0x60, 0x6d);
    private static final Color NODE_BORDER_COLOR = new Color(0x47, 0x55, 0x69);
    private static final Color EDGE_COLOR = new Color(0x94, 0xa3, 0xb8, 96);
    private static final Color INTRA_EDGE_COLOR = new Color(0x64, 0x74, 0x8b, 56);
    private static final Font TITLE_FONT = new Font("SansSerif", Font.BOLD, 18);
    private static final Font META_FONT = new Font("SansSerif", Font.PLAIN, 10);
    private static final Font LABEL_FONT = new Font("SansSerif", Font.PLAIN, 9);
    private static final Comparator<Node> NODE_ORDER = (left, right) -> {
        int labelCompare = left.label.compareTo(right.label);
        if (labelCompare != 0) {
            return labelCompare;
        }
        return left.nodeId.compareTo(right.nodeId);
    };

    public static void main(String[] args) throws Exception {
        Path dotPath = Path.of(args.length >= 1 ? args[0] : "cg/callgraph.dot");
        Path pngPath = Path.of(args.length >= 2 ? args[1] : "cg/callgraph.png");

        GraphData graph = parseDot(dotPath);
        GraphLayout layout = buildLayout(graph);
        writePng(graph, layout, pngPath);

        System.out.println(
            "Wrote " + pngPath + " with " + graph.nodes.size() +
            " nodes and " + graph.edges.size() + " edges."
        );
    }

    private static GraphData parseDot(Path dotPath) throws IOException {
        Map<String, Node> nodes = new HashMap<>();
        List<Edge> edges = new ArrayList<>();

        for (String rawLine : Files.readAllLines(dotPath)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.equals("digraph callgraph {") || line.equals("}")) {
                continue;
            }
            if (line.startsWith("rankdir=") || line.startsWith("graph ") ||
                line.startsWith("node ") || line.startsWith("edge ")) {
                continue;
            }

            Matcher nodeMatcher = NODE_PATTERN.matcher(line);
            if (nodeMatcher.matches()) {
                Node node = new Node(
                    unescapeDot(nodeMatcher.group(1)),
                    unescapeDot(nodeMatcher.group(2)),
                    nodeMatcher.group(3),
                    nodeMatcher.group(4)
                );
                nodes.put(node.nodeId, node);
                continue;
            }

            Matcher edgeMatcher = EDGE_PATTERN.matcher(line);
            if (edgeMatcher.matches()) {
                edges.add(new Edge(
                    unescapeDot(edgeMatcher.group(1)),
                    unescapeDot(edgeMatcher.group(2))
                ));
            }
        }

        return new GraphData(nodes, edges);
    }

    private static GraphLayout buildLayout(GraphData graph) {
        List<List<Node>> components = computeStronglyConnectedComponents(graph);
        Map<String, Integer> componentByNodeId = new HashMap<>();
        for (int i = 0; i < components.size(); i++) {
            for (Node node : components.get(i)) {
                componentByNodeId.put(node.nodeId, i);
            }
        }

        List<Set<Integer>> dagSuccessors = new ArrayList<>();
        List<Integer> indegrees = new ArrayList<>();
        List<String> componentKeys = new ArrayList<>();
        for (List<Node> component : components) {
            dagSuccessors.add(new TreeSet<>());
            indegrees.add(0);
            componentKeys.add(component.get(0).label + "|" + component.get(0).nodeId);
        }

        for (Edge edge : graph.edges) {
            Integer sourceComponent = componentByNodeId.get(edge.sourceId);
            Integer targetComponent = componentByNodeId.get(edge.targetId);
            if (sourceComponent == null || targetComponent == null || sourceComponent.equals(targetComponent)) {
                continue;
            }
            if (dagSuccessors.get(sourceComponent).add(targetComponent)) {
                indegrees.set(targetComponent, indegrees.get(targetComponent) + 1);
            }
        }

        List<Integer> ready = new ArrayList<>();
        for (int i = 0; i < indegrees.size(); i++) {
            if (indegrees.get(i) == 0) {
                ready.add(i);
            }
        }
        ready.sort((left, right) -> componentKeys.get(left).compareTo(componentKeys.get(right)));

        List<Integer> topoOrder = new ArrayList<>();
        while (!ready.isEmpty()) {
            Integer componentIndex = ready.remove(0);
            topoOrder.add(componentIndex);
            for (Integer successor : dagSuccessors.get(componentIndex)) {
                indegrees.set(successor, indegrees.get(successor) - 1);
                if (indegrees.get(successor) == 0) {
                    ready.add(successor);
                    ready.sort((left, right) -> componentKeys.get(left).compareTo(componentKeys.get(right)));
                }
            }
        }

        List<Integer> componentLayers = new ArrayList<>();
        for (int i = 0; i < components.size(); i++) {
            componentLayers.add(0);
        }
        for (Integer componentIndex : topoOrder) {
            for (Integer successor : dagSuccessors.get(componentIndex)) {
                componentLayers.set(
                    successor,
                    Math.max(componentLayers.get(successor), componentLayers.get(componentIndex) + 1)
                );
            }
        }

        TreeMap<Integer, List<Node>> layerMap = new TreeMap<>();
        for (int i = 0; i < components.size(); i++) {
            List<Node> componentNodes = new ArrayList<>(components.get(i));
            componentNodes.sort(NODE_ORDER);
            List<Node> layerNodes = layerMap.computeIfAbsent(componentLayers.get(i), ignored -> new ArrayList<>());
            layerNodes.addAll(componentNodes);
        }
        for (List<Node> layerNodes : layerMap.values()) {
            layerNodes.sort(NODE_ORDER);
        }

        List<List<Node>> orderedLayers = new ArrayList<>(layerMap.values());
        int maxLayerSize = 1;
        for (List<Node> layerNodes : orderedLayers) {
            maxLayerSize = Math.max(maxLayerSize, layerNodes.size());
        }

        int bodyHeight = BOX_HEIGHT + ((maxLayerSize - 1) * ROW_GAP);
        int width = (MARGIN_X * 2) + BOX_WIDTH + (Math.max(1, orderedLayers.size()) - 1) * LAYER_GAP;
        int height = HEADER_HEIGHT + (MARGIN_Y * 2) + bodyHeight;

        List<NodeLayout> nodeLayouts = new ArrayList<>();
        Map<String, NodeLayout> positions = new HashMap<>();
        int layerIndex = 0;
        for (List<Node> layerNodes : orderedLayers) {
            int totalLayerHeight = BOX_HEIGHT + ((layerNodes.size() - 1) * ROW_GAP);
            int x = MARGIN_X + (layerIndex * LAYER_GAP);
            int yStart = HEADER_HEIGHT + MARGIN_Y + ((bodyHeight - totalLayerHeight) / 2);
            for (int rowIndex = 0; rowIndex < layerNodes.size(); rowIndex++) {
                Node node = layerNodes.get(rowIndex);
                NodeLayout nodeLayout = new NodeLayout(
                    node,
                    layerIndex,
                    x,
                    yStart + (rowIndex * ROW_GAP)
                );
                nodeLayouts.add(nodeLayout);
                positions.put(node.nodeId, nodeLayout);
            }
            layerIndex++;
        }

        nodeLayouts.sort((left, right) -> {
            if (left.layer != right.layer) {
                return Integer.compare(left.layer, right.layer);
            }
            return NODE_ORDER.compare(left.node, right.node);
        });

        return new GraphLayout(width, height, orderedLayers.size(), nodeLayouts, positions);
    }

    private static List<List<Node>> computeStronglyConnectedComponents(GraphData graph) {
        Map<String, List<String>> adjacency = buildAdjacency(graph);
        Map<String, Integer> indexByNodeId = new HashMap<>();
        Map<String, Integer> lowLinkByNodeId = new HashMap<>();
        List<String> stack = new ArrayList<>();
        Set<String> onStack = new TreeSet<>();
        List<List<Node>> components = new ArrayList<>();
        int[] nextIndex = { 0 };

        List<Node> orderedNodes = new ArrayList<>(graph.nodes.values());
        orderedNodes.sort(NODE_ORDER);
        for (Node node : orderedNodes) {
            if (!indexByNodeId.containsKey(node.nodeId)) {
                strongConnect(
                    node,
                    graph,
                    adjacency,
                    indexByNodeId,
                    lowLinkByNodeId,
                    stack,
                    onStack,
                    components,
                    nextIndex
                );
            }
        }

        return components;
    }

    private static void strongConnect(
        Node node,
        GraphData graph,
        Map<String, List<String>> adjacency,
        Map<String, Integer> indexByNodeId,
        Map<String, Integer> lowLinkByNodeId,
        List<String> stack,
        Set<String> onStack,
        List<List<Node>> components,
        int[] nextIndex
    ) {
        indexByNodeId.put(node.nodeId, nextIndex[0]);
        lowLinkByNodeId.put(node.nodeId, nextIndex[0]);
        nextIndex[0]++;
        stack.add(node.nodeId);
        onStack.add(node.nodeId);

        for (String neighborId : adjacency.get(node.nodeId)) {
            if (!indexByNodeId.containsKey(neighborId)) {
                strongConnect(
                    graph.nodes.get(neighborId),
                    graph,
                    adjacency,
                    indexByNodeId,
                    lowLinkByNodeId,
                    stack,
                    onStack,
                    components,
                    nextIndex
                );
                lowLinkByNodeId.put(
                    node.nodeId,
                    Math.min(lowLinkByNodeId.get(node.nodeId), lowLinkByNodeId.get(neighborId))
                );
            } else if (onStack.contains(neighborId)) {
                lowLinkByNodeId.put(
                    node.nodeId,
                    Math.min(lowLinkByNodeId.get(node.nodeId), indexByNodeId.get(neighborId))
                );
            }
        }

        if (lowLinkByNodeId.get(node.nodeId).equals(indexByNodeId.get(node.nodeId))) {
            List<Node> component = new ArrayList<>();
            while (!stack.isEmpty()) {
                String memberId = stack.remove(stack.size() - 1);
                onStack.remove(memberId);
                component.add(graph.nodes.get(memberId));
                if (memberId.equals(node.nodeId)) {
                    break;
                }
            }
            component.sort(NODE_ORDER);
            components.add(component);
        }
    }

    private static Map<String, List<String>> buildAdjacency(GraphData graph) {
        Map<String, List<String>> adjacency = new HashMap<>();
        for (Node node : graph.nodes.values()) {
            adjacency.put(node.nodeId, new ArrayList<>());
        }
        List<Edge> orderedEdges = new ArrayList<>(graph.edges);
        orderedEdges.sort((left, right) -> {
            int sourceCompare = left.sourceId.compareTo(right.sourceId);
            if (sourceCompare != 0) {
                return sourceCompare;
            }
            return left.targetId.compareTo(right.targetId);
        });
        for (Edge edge : orderedEdges) {
            List<String> neighbors = adjacency.get(edge.sourceId);
            if (neighbors != null) {
                neighbors.add(edge.targetId);
            }
        }
        return adjacency;
    }

    private static void writePng(GraphData graph, GraphLayout layout, Path pngPath) throws IOException {
        BufferedImage image = new BufferedImage(layout.width, layout.height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            graphics.setColor(BACKGROUND_COLOR);
            graphics.fillRect(0, 0, layout.width, layout.height);

            graphics.setColor(TITLE_COLOR);
            graphics.setFont(TITLE_FONT);
            graphics.drawString("Call Graph", 24, 28);

            graphics.setColor(META_COLOR);
            graphics.setFont(META_FONT);
            graphics.drawString(
                "nodes=" + graph.nodes.size() +
                " edges=" + graph.edges.size() +
                " layers=" + layout.layerCount,
                24,
                46
            );

            drawEdges(graphics, graph, layout);
            drawNodes(graphics, layout);
        } finally {
            graphics.dispose();
        }

        Files.createDirectories(pngPath.getParent());
        ImageIO.write(image, "png", pngPath.toFile());
    }

    private static void drawEdges(Graphics2D graphics, GraphData graph, GraphLayout layout) {
        List<Edge> orderedEdges = new ArrayList<>(graph.edges);
        orderedEdges.sort((left, right) -> {
            int sourceCompare = left.sourceId.compareTo(right.sourceId);
            if (sourceCompare != 0) {
                return sourceCompare;
            }
            return left.targetId.compareTo(right.targetId);
        });

        BasicStroke interLayerStroke = new BasicStroke(1.0f);
        BasicStroke intraLayerStroke = new BasicStroke(
            1.0f,
            BasicStroke.CAP_BUTT,
            BasicStroke.JOIN_ROUND,
            10.0f,
            new float[] { 2.0f, 3.0f },
            0.0f
        );

        for (Edge edge : orderedEdges) {
            NodeLayout source = layout.positions.get(edge.sourceId);
            NodeLayout target = layout.positions.get(edge.targetId);
            if (source == null || target == null) {
                continue;
            }

            int startX = source.x + BOX_WIDTH;
            int startY = source.y + (BOX_HEIGHT / 2);
            int endX = target.x;
            int endY = target.y + (BOX_HEIGHT / 2);
            int midX = (startX + endX) / 2;
            Shape curve = new CubicCurve2D.Float(
                startX,
                startY,
                midX,
                startY,
                midX,
                endY,
                endX,
                endY
            );

            if (source.layer == target.layer) {
                graphics.setStroke(intraLayerStroke);
                graphics.setColor(INTRA_EDGE_COLOR);
            } else {
                graphics.setStroke(interLayerStroke);
                graphics.setColor(EDGE_COLOR);
            }
            graphics.draw(curve);
        }
    }

    private static void drawNodes(Graphics2D graphics, GraphLayout layout) {
        graphics.setFont(LABEL_FONT);
        for (NodeLayout nodeLayout : layout.nodes) {
            Shape shape;
            if ("ellipse".equals(nodeLayout.node.shape)) {
                shape = new Ellipse2D.Float(nodeLayout.x, nodeLayout.y, BOX_WIDTH, BOX_HEIGHT);
            } else {
                shape = new RoundRectangle2D.Float(nodeLayout.x, nodeLayout.y, BOX_WIDTH, BOX_HEIGHT, 6, 6);
            }

            graphics.setColor(parseHexColor(nodeLayout.node.fillColor));
            graphics.fill(shape);
            graphics.setColor(NODE_BORDER_COLOR);
            graphics.draw(shape);

            graphics.setColor(TITLE_COLOR);
            graphics.drawString(
                truncateLabel(nodeLayout.node.label, 20),
                nodeLayout.x + 4,
                nodeLayout.y + BOX_HEIGHT - 5
            );
        }
    }

    private static String truncateLabel(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private static Color parseHexColor(String hexColor) {
        return new Color(
            Integer.parseInt(hexColor.substring(1, 3), 16),
            Integer.parseInt(hexColor.substring(3, 5), 16),
            Integer.parseInt(hexColor.substring(5, 7), 16)
        );
    }

    private static String unescapeDot(String value) {
        return value.replace("\\\\", "\\").replace("\\\"", "\"");
    }

    private record Node(String nodeId, String label, String fillColor, String shape) {}
    private record Edge(String sourceId, String targetId) {}
    private record GraphData(Map<String, Node> nodes, List<Edge> edges) {}
    private record NodeLayout(Node node, int layer, int x, int y) {}
    private record GraphLayout(
        int width,
        int height,
        int layerCount,
        List<NodeLayout> nodes,
        Map<String, NodeLayout> positions
    ) {}
}
