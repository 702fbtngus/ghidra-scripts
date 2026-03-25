// Build and visualize the whole-program call graph.
//@author
//@category AAA
//@keybinding
//@menupath
//@toolbar
//@runtime Java

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
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.imageio.ImageIO;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.CallGraphType;
import ghidra.graph.ProgramGraphType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.service.graph.GraphDisplayOptionsBuilder;
import ghidra.service.graph.VertexShape;

public class CallGraphBuilder extends GhidraScript {

    private static final String INTERNAL_VERTEX_TYPE = ProgramGraphType.BODY;
    private static final String EXTERNAL_VERTEX_TYPE = ProgramGraphType.EXTERNAL;
    private static final String VISITED_INTERNAL_VERTEX_TYPE = "Visited Internal";
    private static final String VISITED_EXTERNAL_VERTEX_TYPE = "Visited External";
    private static final String BRANCH_INTERNAL_VERTEX_TYPE = "Observed Branch Internal";
    private static final String BRANCH_EXTERNAL_VERTEX_TYPE = "Observed Branch External";
    private static final String VISITED_BRANCH_INTERNAL_VERTEX_TYPE = "Visited Observed Branch Internal";
    private static final String VISITED_BRANCH_EXTERNAL_VERTEX_TYPE = "Visited Observed Branch External";
    private static final String VISITED_EDGE_TYPE = "Visited Edge";
    private static final String BRANCH_EDGE_TYPE = "Observed Branch";
    private static final String VISITED_BRANCH_EDGE_TYPE = "Visited Observed Branch";
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
    private static final Color VISITED_EDGE_COLOR = new Color(0x16, 0xa3, 0x4a, 152);
    private static final Color VISITED_INTRA_EDGE_COLOR = new Color(0x16, 0xa3, 0x4a, 96);
    private static final Color BRANCH_EDGE_COLOR = new Color(0xdc, 0x26, 0x26, 168);
    private static final Color BRANCH_INTRA_EDGE_COLOR = new Color(0xdc, 0x26, 0x26, 112);
    private static final Color VISITED_BRANCH_EDGE_COLOR = new Color(0xf5, 0x9e, 0x0b, 176);
    private static final Color VISITED_BRANCH_INTRA_EDGE_COLOR = new Color(0xf5, 0x9e, 0x0b, 120);
    private static final Font TITLE_FONT = new Font("SansSerif", Font.BOLD, 18);
    private static final Font META_FONT = new Font("SansSerif", Font.PLAIN, 10);
    private static final Font LABEL_FONT = new Font("SansSerif", Font.PLAIN, 9);
    private static final Comparator<Function> FUNCTION_ORDER = (left, right) -> {
        int addressCompare = left.getEntryPoint().compareTo(right.getEntryPoint());
        if (addressCompare != 0) {
            return addressCompare;
        }
        return left.getName().compareTo(right.getName());
    };
    private static final Comparator<AttributedVertex> VERTEX_ORDER = (left, right) -> {
        int nameCompare = left.getName().compareTo(right.getName());
        if (nameCompare != 0) {
            return nameCompare;
        }
        return left.getId().compareTo(right.getId());
    };
    private static final Comparator<AttributedVertex> VERTEX_ID_ORDER = (left, right) ->
        left.getId().compareTo(right.getId());
    private final Map<String, AttributedVertex> vertexCache = new HashMap<>();
    private int observedBranchEntryCount;
    private int observedBranchEdgeCount;
    private int unresolvedBranchEntryCount;
    private int visitedNodeCount;
    private int visitedEdgeCount;
    private int unresolvedVisitedAddressCount;

    @Override
    protected void run() throws Exception {
        List<Function> functions = getAllFunctions();
        AttributedGraph staticGraph = createGraph("Static Call Graph");
        vertexCache.clear();
        buildCallGraph(staticGraph, functions);
        Path staticDotPath = writeDotFile(staticGraph, "callgraph_static.dot");
        Path staticPngPath = writePngFile(
            staticGraph,
            "Static Call Graph",
            "nodes=" + staticGraph.getVertexCount() +
            " edges=" + staticGraph.getEdgeCount(),
            "callgraph_static.png"
        );

        AttributedGraph graph = createGraph("Call Graph");
        vertexCache.clear();
        List<TraceEntry> traceEntries = loadInstructionTraceEntries();
        buildCallGraph(graph, functions);
        highlightObservedBranches(graph, traceEntries);
        highlightVisitedExecution(graph, traceEntries);
        Path dotPath = writeDotFile(graph, "callgraph.dot");
        Path pngPath = writePngFile(
            graph,
            "Call Graph",
            "nodes=" + graph.getVertexCount() +
            " edges=" + graph.getEdgeCount() +
            " layers=" + buildLayout(graph).layerCount +
            " redBranches=" + observedBranchEdgeCount +
            " greenVisited=" + visitedEdgeCount,
            "callgraph.png"
        );

        println("Program: " + currentProgram.getName());
        println("Functions in graph: " + staticGraph.getVertexCount());
        println("Static graph edges total: " + staticGraph.getEdgeCount());
        println("Static DOT export: " + staticDotPath.toAbsolutePath());
        println("Static PNG export: " + staticPngPath.toAbsolutePath());
        println("Dynamic graph edges total: " + graph.getEdgeCount());
        println("Observed branch entries: " + observedBranchEntryCount);
        println("Observed branch edges highlighted: " + observedBranchEdgeCount);
        println("Observed branch entries unresolved: " + unresolvedBranchEntryCount);
        println("Visited nodes highlighted: " + visitedNodeCount);
        println("Visited edges highlighted: " + visitedEdgeCount);
        println("Visited addresses unresolved: " + unresolvedVisitedAddressCount);
        println("DOT export: " + dotPath.toAbsolutePath());
        println("PNG export: " + pngPath.toAbsolutePath());

        if (showGraph(graph)) {
            println("Displayed call graph in Ghidra.");
        } else {
            println("Graph display service unavailable; PNG and DOT files were still generated.");
        }
    }

    private AttributedGraph createGraph(String title) {
        return new AttributedGraph(
            title,
            new CallGraphType(),
            "Whole-program call graph for " + currentProgram.getName()
        );
    }

    private List<Function> getAllFunctions() {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator iterator = functionManager.getFunctions(true);
        List<Function> functions = new ArrayList<>();

        while (iterator.hasNext() && !monitor.isCancelled()) {
            functions.add(iterator.next());
        }

        functions.sort(FUNCTION_ORDER);
        return functions;
    }

    private void buildCallGraph(AttributedGraph graph, List<Function> functions) throws Exception {
        monitor.setMessage("Building call graph");

        for (Function function : functions) {
            monitor.checkCancelled();
            getOrCreateVertex(graph, function);
        }

        for (Function caller : functions) {
            monitor.checkCancelled();

            AttributedVertex callerVertex = getOrCreateVertex(graph, caller);
            List<Function> callees = sortFunctions(caller.getCalledFunctions(monitor));
            for (Function callee : callees) {
                monitor.checkCancelled();
                AttributedVertex calleeVertex = getOrCreateVertex(graph, callee);
                graph.addEdge(callerVertex, calleeVertex);
            }
        }
    }

    private AttributedVertex getOrCreateVertex(AttributedGraph graph, Function function) {
        String vertexId = function.getEntryPoint().toString();
        AttributedVertex existing = vertexCache.get(vertexId);
        if (existing != null) {
            return existing;
        }

        AttributedVertex vertex = graph.addVertex(vertexId, buildVertexName(function));
        vertex.setVertexType(function.isExternal() ? EXTERNAL_VERTEX_TYPE : INTERNAL_VERTEX_TYPE);
        vertex.setDescription(buildVertexDescription(function));
        vertexCache.put(vertexId, vertex);
        return vertex;
    }

    private String buildVertexName(Function function) {
        StringBuilder name = new StringBuilder(function.getName());
        if (function.isThunk()) {
            name.append(" [thunk]");
        }
        return name.toString();
    }

    private String buildVertexDescription(Function function) {
        StringBuilder description = new StringBuilder("<html>");
        description.append("<b>").append(escapeHtml(function.getName())).append("</b><br/>");
        description.append("Entry: ").append(escapeHtml(function.getEntryPoint().toString())).append("<br/>");
        description.append("External: ").append(function.isExternal()).append("<br/>");
        description.append("Thunk: ").append(function.isThunk());

        if (function.isThunk()) {
            Function thunked = function.getThunkedFunction(true);
            if (thunked != null) {
                description.append("<br/>Thunk target: ")
                    .append(escapeHtml(thunked.getName()))
                    .append(" @ ")
                    .append(escapeHtml(thunked.getEntryPoint().toString()));
            }
        }

        description.append("</html>");
        return description.toString();
    }

    private boolean showGraph(AttributedGraph graph) throws Exception {
        PluginTool tool = state == null ? null : state.getTool();
        if (tool == null) {
            return false;
        }

        GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
        if (broker == null || !broker.hasDefaultGraphDisplayProvider()) {
            return false;
        }

        GraphDisplay display = broker.getDefaultGraphDisplay(false, monitor);
        GraphDisplayOptions options = new GraphDisplayOptionsBuilder(graph.getGraphType())
            .vertex(INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0x7d, 0xc3, 0xf7))
            .vertex(EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xf6, 0xd5, 0x8b))
            .vertex(VISITED_INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0xbb, 0xf7, 0xd0))
            .vertex(VISITED_EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xbb, 0xf7, 0xd0))
            .vertex(BRANCH_INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0xfe, 0xca, 0xca))
            .vertex(BRANCH_EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xfecaca))
            .vertex(VISITED_BRANCH_INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0xfd, 0xba, 0x74))
            .vertex(VISITED_BRANCH_EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xfd, 0xba, 0x74))
            .edge(VISITED_EDGE_TYPE, new Color(0x16, 0xa3, 0x4a))
            .edge(BRANCH_EDGE_TYPE, new Color(0xdc, 0x26, 0x26))
            .edge(VISITED_BRANCH_EDGE_TYPE, new Color(0xf5, 0x9e, 0x0b))
            .defaultVertexColor(new Color(0xc7, 0xd2, 0xda))
            .defaultEdgeColor(new Color(0x55, 0x66, 0x77))
            .defaultLayoutAlgorithm("Compact Hierarchical")
            .maxNodeCount(Math.max(1000, graph.getVertexCount() + 1))
            .build();

        display.setGraph(graph, options,
            currentProgram.getName() + " - Call Graph", false, monitor);
        return true;
    }

    private Path writePngFile(
        AttributedGraph graph,
        String title,
        String metadata,
        String filename
    ) throws IOException {
        GraphLayout layout = buildLayout(graph);
        BufferedImage image = new BufferedImage(
            layout.width,
            layout.height,
            BufferedImage.TYPE_INT_ARGB
        );
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            graphics.setColor(BACKGROUND_COLOR);
            graphics.fillRect(0, 0, layout.width, layout.height);

            graphics.setColor(TITLE_COLOR);
            graphics.setFont(TITLE_FONT);
            graphics.drawString(title, 24, 28);

            graphics.setColor(META_COLOR);
            graphics.setFont(META_FONT);
            graphics.drawString(metadata, 24, 46);

            drawEdges(graphics, graph, layout);
            drawNodes(graphics, layout);
        } finally {
            graphics.dispose();
        }

        Path outPath = getOutputPath(filename);
        Files.createDirectories(outPath.getParent());
        ImageIO.write(image, "png", outPath.toFile());
        return outPath;
    }

    private void drawEdges(Graphics2D graphics, AttributedGraph graph, GraphLayout layout) {
        List<AttributedEdge> edges = getSortedEdges(graph);

        BasicStroke interLayerStroke = new BasicStroke(1.0f);
        BasicStroke intraLayerStroke = new BasicStroke(
            1.0f,
            BasicStroke.CAP_BUTT,
            BasicStroke.JOIN_ROUND,
            10.0f,
            new float[] { 2.0f, 3.0f },
            0.0f
        );

        for (AttributedEdge edge : edges) {
            AttributedVertex sourceVertex = graph.getEdgeSource(edge);
            AttributedVertex targetVertex = graph.getEdgeTarget(edge);
            NodeLayout source = layout.positions.get(sourceVertex.getId());
            NodeLayout target = layout.positions.get(targetVertex.getId());
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

            if (isVisitedBranchEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? VISITED_BRANCH_INTRA_EDGE_COLOR : VISITED_BRANCH_EDGE_COLOR);
            } else if (isObservedBranchEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? BRANCH_INTRA_EDGE_COLOR : BRANCH_EDGE_COLOR);
            } else if (isVisitedEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? VISITED_INTRA_EDGE_COLOR : VISITED_EDGE_COLOR);
            } else if (source.layer == target.layer) {
                graphics.setStroke(intraLayerStroke);
                graphics.setColor(INTRA_EDGE_COLOR);
            } else {
                graphics.setStroke(interLayerStroke);
                graphics.setColor(EDGE_COLOR);
            }
            graphics.draw(curve);
        }
    }

    private void drawNodes(Graphics2D graphics, GraphLayout layout) {
        graphics.setFont(LABEL_FONT);
        for (NodeLayout nodeLayout : layout.nodes) {
            Shape shape;
            if (isExternalVertexType(nodeLayout.vertex.getVertexType())) {
                shape = new Ellipse2D.Float(nodeLayout.x, nodeLayout.y, BOX_WIDTH, BOX_HEIGHT);
            } else {
                shape = new RoundRectangle2D.Float(
                    nodeLayout.x,
                    nodeLayout.y,
                    BOX_WIDTH,
                    BOX_HEIGHT,
                    6,
                    6
                );
            }

            graphics.setColor(parseHexColor(nodeLayout.fillColor));
            graphics.fill(shape);
            graphics.setColor(NODE_BORDER_COLOR);
            graphics.draw(shape);

            graphics.setColor(TITLE_COLOR);
            graphics.drawString(
                truncateLabel(nodeLayout.vertex.getName(), 20),
                nodeLayout.x + 4,
                nodeLayout.y + BOX_HEIGHT - 5
            );
        }
    }

    private GraphLayout buildLayout(AttributedGraph graph) {
        List<AttributedVertex> vertices = new ArrayList<>(graph.vertexSet());
        vertices.sort(VERTEX_ORDER);

        List<List<AttributedVertex>> components = computeStronglyConnectedComponents(graph, vertices);
        Map<String, Integer> componentByVertexId = new HashMap<>();
        for (int i = 0; i < components.size(); i++) {
            for (AttributedVertex vertex : components.get(i)) {
                componentByVertexId.put(vertex.getId(), i);
            }
        }

        List<Set<Integer>> dagSuccessors = new ArrayList<>();
        List<Integer> indegrees = new ArrayList<>();
        List<String> componentKeys = new ArrayList<>();
        for (List<AttributedVertex> component : components) {
            dagSuccessors.add(new TreeSet<>());
            indegrees.add(0);
            componentKeys.add(componentSortKey(component));
        }

        for (AttributedEdge edge : graph.edgeSet()) {
            AttributedVertex sourceVertex = graph.getEdgeSource(edge);
            AttributedVertex targetVertex = graph.getEdgeTarget(edge);
            Integer sourceComponent = componentByVertexId.get(sourceVertex.getId());
            Integer targetComponent = componentByVertexId.get(targetVertex.getId());
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

        TreeMap<Integer, List<AttributedVertex>> layerMap = new TreeMap<>();
        for (int i = 0; i < components.size(); i++) {
            List<AttributedVertex> componentVertices = new ArrayList<>(components.get(i));
            componentVertices.sort(VERTEX_ORDER);
            List<AttributedVertex> layerVertices = layerMap.computeIfAbsent(
                componentLayers.get(i),
                ignored -> new ArrayList<>()
            );
            layerVertices.addAll(componentVertices);
        }
        for (List<AttributedVertex> layerVertices : layerMap.values()) {
            layerVertices.sort(VERTEX_ORDER);
        }

        List<List<AttributedVertex>> orderedLayers = new ArrayList<>(layerMap.values());
        int maxLayerSize = 1;
        for (List<AttributedVertex> layerVertices : orderedLayers) {
            maxLayerSize = Math.max(maxLayerSize, layerVertices.size());
        }

        int bodyHeight = BOX_HEIGHT + ((maxLayerSize - 1) * ROW_GAP);
        int width = (MARGIN_X * 2) + BOX_WIDTH + (Math.max(1, orderedLayers.size()) - 1) * LAYER_GAP;
        int height = HEADER_HEIGHT + (MARGIN_Y * 2) + bodyHeight;

        List<NodeLayout> nodeLayouts = new ArrayList<>();
        Map<String, NodeLayout> positions = new HashMap<>();

        int layerIndex = 0;
        for (List<AttributedVertex> layerVertices : orderedLayers) {
            int totalLayerHeight = BOX_HEIGHT + ((layerVertices.size() - 1) * ROW_GAP);
            int x = MARGIN_X + (layerIndex * LAYER_GAP);
            int yStart = HEADER_HEIGHT + MARGIN_Y + ((bodyHeight - totalLayerHeight) / 2);

            for (int rowIndex = 0; rowIndex < layerVertices.size(); rowIndex++) {
                AttributedVertex vertex = layerVertices.get(rowIndex);
                NodeLayout nodeLayout = new NodeLayout(
                    vertex,
                    layerIndex,
                    x,
                    yStart + (rowIndex * ROW_GAP),
                    getVertexFillColor(vertex)
                );
                nodeLayouts.add(nodeLayout);
                positions.put(vertex.getId(), nodeLayout);
            }
            layerIndex++;
        }

        nodeLayouts.sort((left, right) -> {
            if (left.layer != right.layer) {
                return Integer.compare(left.layer, right.layer);
            }
            return VERTEX_ORDER.compare(left.vertex, right.vertex);
        });

        return new GraphLayout(width, height, orderedLayers.size(), nodeLayouts, positions);
    }

    private void highlightObservedBranches(AttributedGraph graph, List<TraceEntry> traceEntries) throws Exception {
        observedBranchEntryCount = 0;
        observedBranchEdgeCount = 0;
        unresolvedBranchEntryCount = 0;
        if (traceEntries.isEmpty()) {
            return;
        }

        Set<String> highlightedEdges = new TreeSet<>();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        TraceEntry previousEntry = null;
        for (TraceEntry currentEntry : traceEntries) {
            monitor.checkCancelled();

            if (previousEntry == null) {
                previousEntry = currentEntry;
                continue;
            }

            Instruction previousInstruction = getInstructionAt(toAddr(previousEntry.addressValue));
            boolean interruptReturn = previousEntry.interrupted && !currentEntry.interrupted;
            if (previousInstruction == null ||
                previousInstruction.getFlowType().isTerminal() ||
                interruptReturn ||
                isExpectedSuccessor(previousInstruction, currentEntry.addressValue)) {
                previousEntry = currentEntry;
                continue;
            }

            observedBranchEntryCount++;
            AttributedVertex sourceVertex = resolveBranchVertex(graph, functionManager, previousEntry.addressValue);
            AttributedVertex targetVertex = resolveBranchVertex(graph, functionManager, currentEntry.addressValue);
            markObservedBranchVertex(sourceVertex);
            markObservedBranchVertex(targetVertex);

            AttributedEdge edge = graph.addEdge(sourceVertex, targetVertex);
            markObservedBranchEdge(edge);
            highlightedEdges.add(sourceVertex.getId() + "->" + targetVertex.getId());
            previousEntry = currentEntry;
        }

        observedBranchEdgeCount = highlightedEdges.size();
    }

    private void highlightVisitedExecution(AttributedGraph graph, List<TraceEntry> traceEntries) throws Exception {
        visitedNodeCount = 0;
        visitedEdgeCount = 0;
        unresolvedVisitedAddressCount = 0;
        if (traceEntries.isEmpty()) {
            return;
        }

        Set<String> visitedVertices = new TreeSet<>();
        Set<String> visitedEdges = new TreeSet<>();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        AttributedVertex previousVertex = null;
        TraceEntry previousEntry = null;
        for (TraceEntry currentEntry : traceEntries) {
            monitor.checkCancelled();

            AttributedVertex currentVertex = resolveTraceVertex(graph, functionManager, currentEntry.addressValue);
            if (currentVertex == null) {
                unresolvedVisitedAddressCount++;
                previousVertex = null;
                previousEntry = currentEntry;
                continue;
            }

            markVisitedVertex(currentVertex);
            visitedVertices.add(currentVertex.getId());

            if (previousVertex != null && !previousVertex.getId().equals(currentVertex.getId())) {
                Instruction previousInstruction = getInstructionAt(toAddr(previousEntry.addressValue));
                if (previousInstruction != null && !previousInstruction.getFlowType().isTerminal()) {
                    AttributedEdge edge = graph.addEdge(previousVertex, currentVertex);
                    markVisitedEdge(edge);
                    visitedEdges.add(previousVertex.getId() + "->" + currentVertex.getId());
                }
            }

            previousVertex = currentVertex;
            previousEntry = currentEntry;
        }

        visitedNodeCount = visitedVertices.size();
        visitedEdgeCount = visitedEdges.size();
    }

    private List<TraceEntry> loadInstructionTraceEntries() throws IOException {
        Path instrLogPath = getInputLogPath("instr.log");
        if (!Files.exists(instrLogPath)) {
            return new ArrayList<>();
        }

        List<TraceEntry> traceEntries = new ArrayList<>();
        for (String line : Files.readAllLines(instrLogPath)) {
            TraceEntry entry = parseInstructionLogEntry(line);
            if (entry != null) {
                traceEntries.add(entry);
            }
        }
        return traceEntries;
    }

    private TraceEntry parseInstructionLogEntry(String line) {
        Long addressValue = parseInstructionLogAddress(line);
        if (addressValue == null) {
            return null;
        }
        return new TraceEntry(addressValue, line.startsWith("[ intr"));
    }

    private Long parseInstructionLogAddress(String line) {
        int addressIndex = line.indexOf("0x");
        if (addressIndex < 0) {
            return null;
        }

        int endIndex = addressIndex + 2;
        while (endIndex < line.length()) {
            char ch = line.charAt(endIndex);
            if (!isHexDigit(ch)) {
                break;
            }
            endIndex++;
        }
        if (endIndex <= addressIndex + 2) {
            return null;
        }

        try {
            return Long.parseUnsignedLong(line.substring(addressIndex + 2, endIndex), 16);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private boolean isHexDigit(char ch) {
        return (
            (ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= 'f') ||
            (ch >= 'A' && ch <= 'F')
        );
    }

    private AttributedVertex resolveBranchVertex(
        AttributedGraph graph,
        FunctionManager functionManager,
        long addressValue
    ) {
        Function function = functionManager.getFunctionContaining(toAddr(addressValue));
        if (function != null) {
            return getOrCreateVertex(graph, function);
        }

        String vertexId = "addr:" + Long.toHexString(addressValue);
        AttributedVertex existing = graph.getVertex(vertexId);
        if (existing != null) {
            return existing;
        }

        String addressLabel = String.format("0x%08x", addressValue);
        AttributedVertex vertex = graph.addVertex(vertexId, addressLabel);
        vertex.setVertexType(BRANCH_EXTERNAL_VERTEX_TYPE);
        vertex.setDescription("<html><b>" + escapeHtml(addressLabel) +
            "</b><br/>Observed branch target/source outside any known function</html>");
        return vertex;
    }

    private AttributedVertex resolveTraceVertex(
        AttributedGraph graph,
        FunctionManager functionManager,
        long addressValue
    ) {
        Function function = functionManager.getFunctionContaining(toAddr(addressValue));
        if (function != null) {
            return getOrCreateVertex(graph, function);
        }

        String vertexId = "addr:" + Long.toHexString(addressValue);
        AttributedVertex existing = graph.getVertex(vertexId);
        if (existing != null) {
            return existing;
        }

        String addressLabel = String.format("0x%08x", addressValue);
        AttributedVertex vertex = graph.addVertex(vertexId, addressLabel);
        vertex.setVertexType(VISITED_EXTERNAL_VERTEX_TYPE);
        vertex.setDescription("<html><b>" + escapeHtml(addressLabel) +
            "</b><br/>Visited execution outside any known function</html>");
        return vertex;
    }

    private void markObservedBranchVertex(AttributedVertex vertex) {
        String vertexType = vertex.getVertexType();
        if (VISITED_BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
            BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return;
        }

        if (VISITED_INTERNAL_VERTEX_TYPE.equals(vertexType)) {
            vertex.setVertexType(VISITED_BRANCH_INTERNAL_VERTEX_TYPE);
        } else if (VISITED_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            vertex.setVertexType(VISITED_BRANCH_EXTERNAL_VERTEX_TYPE);
        } else if (isExternalVertexType(vertexType)) {
            vertex.setVertexType(BRANCH_EXTERNAL_VERTEX_TYPE);
        } else {
            vertex.setVertexType(BRANCH_INTERNAL_VERTEX_TYPE);
        }
    }

    private void markVisitedVertex(AttributedVertex vertex) {
        String vertexType = vertex.getVertexType();
        if (VISITED_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return;
        }

        if (BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType)) {
            vertex.setVertexType(VISITED_BRANCH_INTERNAL_VERTEX_TYPE);
        } else if (BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            vertex.setVertexType(VISITED_BRANCH_EXTERNAL_VERTEX_TYPE);
        } else if (isExternalVertexType(vertexType)) {
            vertex.setVertexType(VISITED_EXTERNAL_VERTEX_TYPE);
        } else {
            vertex.setVertexType(VISITED_INTERNAL_VERTEX_TYPE);
        }
    }

    private void markVisitedEdge(AttributedEdge edge) {
        String edgeType = edge.getEdgeType();
        if (VISITED_BRANCH_EDGE_TYPE.equals(edgeType) || VISITED_EDGE_TYPE.equals(edgeType)) {
            return;
        }

        if (BRANCH_EDGE_TYPE.equals(edgeType)) {
            edge.setEdgeType(VISITED_BRANCH_EDGE_TYPE);
        } else {
            edge.setEdgeType(VISITED_EDGE_TYPE);
        }
    }

    private void markObservedBranchEdge(AttributedEdge edge) {
        String edgeType = edge.getEdgeType();
        if (VISITED_BRANCH_EDGE_TYPE.equals(edgeType) || BRANCH_EDGE_TYPE.equals(edgeType)) {
            return;
        }

        if (VISITED_EDGE_TYPE.equals(edgeType)) {
            edge.setEdgeType(VISITED_BRANCH_EDGE_TYPE);
        } else {
            edge.setEdgeType(BRANCH_EDGE_TYPE);
        }
    }

    private boolean isExpectedSuccessor(Instruction instruction, long nextAddressValue) {
        for (var flow : instruction.getFlows()) {
            if (flow != null && flow.getOffset() == nextAddressValue) {
                return true;
            }
        }

        var fallthrough = instruction.getFallThrough();
        return fallthrough != null && fallthrough.getOffset() == nextAddressValue;
    }

    private List<List<AttributedVertex>> computeStronglyConnectedComponents(
        AttributedGraph graph,
        List<AttributedVertex> vertices
    ) {
        Map<String, List<AttributedVertex>> adjacency = buildAdjacency(graph, vertices);
        Map<String, Integer> indexByVertexId = new HashMap<>();
        Map<String, Integer> lowLinkByVertexId = new HashMap<>();
        List<AttributedVertex> stack = new ArrayList<>();
        Set<String> onStack = new TreeSet<>();
        List<List<AttributedVertex>> components = new ArrayList<>();
        int[] nextIndex = { 0 };

        for (AttributedVertex vertex : vertices) {
            if (!indexByVertexId.containsKey(vertex.getId())) {
                strongConnect(
                    vertex,
                    adjacency,
                    indexByVertexId,
                    lowLinkByVertexId,
                    stack,
                    onStack,
                    components,
                    nextIndex
                );
            }
        }

        return components;
    }

    private void strongConnect(
        AttributedVertex vertex,
        Map<String, List<AttributedVertex>> adjacency,
        Map<String, Integer> indexByVertexId,
        Map<String, Integer> lowLinkByVertexId,
        List<AttributedVertex> stack,
        Set<String> onStack,
        List<List<AttributedVertex>> components,
        int[] nextIndex
    ) {
        indexByVertexId.put(vertex.getId(), nextIndex[0]);
        lowLinkByVertexId.put(vertex.getId(), nextIndex[0]);
        nextIndex[0]++;
        stack.add(vertex);
        onStack.add(vertex.getId());

        for (AttributedVertex neighbor : adjacency.get(vertex.getId())) {
            if (!indexByVertexId.containsKey(neighbor.getId())) {
                strongConnect(
                    neighbor,
                    adjacency,
                    indexByVertexId,
                    lowLinkByVertexId,
                    stack,
                    onStack,
                    components,
                    nextIndex
                );
                lowLinkByVertexId.put(
                    vertex.getId(),
                    Math.min(lowLinkByVertexId.get(vertex.getId()), lowLinkByVertexId.get(neighbor.getId()))
                );
            } else if (onStack.contains(neighbor.getId())) {
                lowLinkByVertexId.put(
                    vertex.getId(),
                    Math.min(lowLinkByVertexId.get(vertex.getId()), indexByVertexId.get(neighbor.getId()))
                );
            }
        }

        if (lowLinkByVertexId.get(vertex.getId()).equals(indexByVertexId.get(vertex.getId()))) {
            List<AttributedVertex> component = new ArrayList<>();
            while (!stack.isEmpty()) {
                AttributedVertex member = stack.remove(stack.size() - 1);
                onStack.remove(member.getId());
                component.add(member);
                if (member.getId().equals(vertex.getId())) {
                    break;
                }
            }
            component.sort(VERTEX_ORDER);
            components.add(component);
        }
    }

    private Map<String, List<AttributedVertex>> buildAdjacency(
        AttributedGraph graph,
        List<AttributedVertex> vertices
    ) {
        Map<String, AttributedVertex> verticesById = new HashMap<>();
        Map<String, List<AttributedVertex>> adjacency = new HashMap<>();
        for (AttributedVertex vertex : vertices) {
            verticesById.put(vertex.getId(), vertex);
            adjacency.put(vertex.getId(), new ArrayList<>());
        }

        List<AttributedEdge> edges = new ArrayList<>(graph.edgeSet());
        edges = getSortedEdges(graph);
        for (AttributedEdge edge : edges) {
            AttributedVertex sourceVertex = graph.getEdgeSource(edge);
            AttributedVertex targetVertex = graph.getEdgeTarget(edge);
            AttributedVertex source = verticesById.get(sourceVertex.getId());
            AttributedVertex target = verticesById.get(targetVertex.getId());
            if (source != null && target != null) {
                adjacency.get(source.getId()).add(target);
            }
        }
        return adjacency;
    }

    private String componentSortKey(List<AttributedVertex> component) {
        AttributedVertex firstVertex = component.get(0);
        return firstVertex.getName() + "|" + firstVertex.getId();
    }

    private Path writeDotFile(AttributedGraph graph, String filename) throws IOException {
        Path outPath = getOutputPath(filename);
        Files.createDirectories(outPath.getParent());

        List<AttributedVertex> vertices = new ArrayList<>(graph.vertexSet());
        vertices.sort(VERTEX_ID_ORDER);

        List<AttributedEdge> edges = getSortedEdges(graph);

        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(outPath))) {
            writer.println("digraph callgraph {");
            writer.println("  rankdir=LR;");
            writer.println("  graph [splines=true, overlap=false];");
            writer.println("  node [style=filled, shape=box, fontname=\"Helvetica\"];");
            writer.println("  edge [fontname=\"Helvetica\"];");

            for (AttributedVertex vertex : vertices) {
                String fillColor = getVertexFillColor(vertex);
                String shape = isExternalVertexType(vertex.getVertexType()) ? "ellipse" : "box";
                writer.printf(
                    "  \"%s\" [label=\"%s\", fillcolor=\"%s\", shape=\"%s\"];%n",
                    escapeDot(vertex.getId()),
                    escapeDot(vertex.getName()),
                    fillColor,
                    shape
                );
            }

            for (AttributedEdge edge : edges) {
                AttributedVertex source = graph.getEdgeSource(edge);
                AttributedVertex target = graph.getEdgeTarget(edge);
                if (isVisitedBranchEdge(edge)) {
                    writer.printf(
                        "  \"%s\" -> \"%s\" [color=\"#f59e0b\", penwidth=\"1.8\"];%n",
                        escapeDot(source.getId()),
                        escapeDot(target.getId())
                    );
                } else if (isObservedBranchEdge(edge)) {
                    writer.printf(
                        "  \"%s\" -> \"%s\" [color=\"#dc2626\", penwidth=\"1.6\"];%n",
                        escapeDot(source.getId()),
                        escapeDot(target.getId())
                    );
                } else if (isVisitedEdge(edge)) {
                    writer.printf(
                        "  \"%s\" -> \"%s\" [color=\"#16a34a\", penwidth=\"1.6\"];%n",
                        escapeDot(source.getId()),
                        escapeDot(target.getId())
                    );
                } else {
                    writer.printf(
                        "  \"%s\" -> \"%s\";%n",
                        escapeDot(source.getId()),
                        escapeDot(target.getId())
                    );
                }
            }

            writer.println("}");
        }

        return outPath;
    }

    private Path getInputLogPath(String filename) {
        return Path.of(
            getSourceFile().getParentFile().getAbsolutePath(),
            "log",
            filename
        );
    }

    private Path getOutputPath(String filename) {
        return Path.of(
            getSourceFile().getParentFile().getAbsolutePath(),
            "cg",
            filename
        );
    }

    private List<AttributedEdge> getSortedEdges(AttributedGraph graph) {
        List<AttributedEdge> edges = new ArrayList<>(graph.edgeSet());
        edges.sort((left, right) -> {
            AttributedVertex leftSource = graph.getEdgeSource(left);
            AttributedVertex rightSource = graph.getEdgeSource(right);
            int sourceCompare = leftSource.getId().compareTo(rightSource.getId());
            if (sourceCompare != 0) {
                return sourceCompare;
            }

            AttributedVertex leftTarget = graph.getEdgeTarget(left);
            AttributedVertex rightTarget = graph.getEdgeTarget(right);
            return leftTarget.getId().compareTo(rightTarget.getId());
        });
        return edges;
    }

    private List<Function> sortFunctions(Set<Function> functions) {
        return sortFunctions((Collection<Function>) functions);
    }

    private List<Function> sortFunctions(Collection<Function> functions) {
        List<Function> sorted = new ArrayList<>(functions);
        sorted.sort(FUNCTION_ORDER);
        return sorted;
    }

    private String escapeHtml(String value) {
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }

    private String escapeDot(String value) {
        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"");
    }

    private String truncateLabel(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private Color parseHexColor(String hexColor) {
        return new Color(
            Integer.parseInt(hexColor.substring(1, 3), 16),
            Integer.parseInt(hexColor.substring(3, 5), 16),
            Integer.parseInt(hexColor.substring(5, 7), 16)
        );
    }

    private boolean isExternalVertexType(String vertexType) {
        return (
            EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
            BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)
        );
    }

    private boolean isVisitedEdge(AttributedEdge edge) {
        String edgeType = edge.getEdgeType();
        return VISITED_EDGE_TYPE.equals(edgeType) || VISITED_BRANCH_EDGE_TYPE.equals(edgeType);
    }

    private boolean isObservedBranchEdge(AttributedEdge edge) {
        String edgeType = edge.getEdgeType();
        return BRANCH_EDGE_TYPE.equals(edgeType) || VISITED_BRANCH_EDGE_TYPE.equals(edgeType);
    }

    private boolean isVisitedBranchEdge(AttributedEdge edge) {
        return VISITED_BRANCH_EDGE_TYPE.equals(edge.getEdgeType());
    }

    private String getVertexFillColor(AttributedVertex vertex) {
        String vertexType = vertex.getVertexType();
        if (VISITED_BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return "#fdba74";
        }
        if (BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) || BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return "#fecaca";
        }
        if (VISITED_INTERNAL_VERTEX_TYPE.equals(vertexType) || VISITED_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return "#bbf7d0";
        }
        if (EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return "#f6d58b";
        }
        return "#7dc3f7";
    }

    private static final class NodeLayout {
        private final AttributedVertex vertex;
        private final int layer;
        private final int x;
        private final int y;
        private final String fillColor;

        private NodeLayout(AttributedVertex vertex, int layer, int x, int y, String fillColor) {
            this.vertex = vertex;
            this.layer = layer;
            this.x = x;
            this.y = y;
            this.fillColor = fillColor;
        }
    }

    private static final class GraphLayout {
        private final int width;
        private final int height;
        private final int layerCount;
        private final List<NodeLayout> nodes;
        private final Map<String, NodeLayout> positions;

        private GraphLayout(
            int width,
            int height,
            int layerCount,
            List<NodeLayout> nodes,
            Map<String, NodeLayout> positions
        ) {
            this.width = width;
            this.height = height;
            this.layerCount = layerCount;
            this.nodes = nodes;
            this.positions = positions;
        }
    }

    private static final class TraceEntry {
        private final long addressValue;
        private final boolean interrupted;

        private TraceEntry(long addressValue, boolean interrupted) {
            this.addressValue = addressValue;
            this.interrupted = interrupted;
        }
    }

}
