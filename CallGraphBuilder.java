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
import java.text.DecimalFormat;
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

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.CallGraphType;
import ghidra.graph.ProgramGraphType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
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
    private static final String REACHABLE_INTERNAL_VERTEX_TYPE = "Reachable Internal";
    private static final String REACHABLE_EXTERNAL_VERTEX_TYPE = "Reachable External";
    private static final String BRANCH_INTERNAL_VERTEX_TYPE = "Observed Branch Internal";
    private static final String BRANCH_EXTERNAL_VERTEX_TYPE = "Observed Branch External";
    private static final String VISITED_BRANCH_INTERNAL_VERTEX_TYPE = "Visited Observed Branch Internal";
    private static final String VISITED_BRANCH_EXTERNAL_VERTEX_TYPE = "Visited Observed Branch External";
    private static final String VISITED_EDGE_TYPE = "Visited Edge";
    private static final String REACHABLE_EDGE_TYPE = "Reachable Edge";
    private static final String BRANCH_EDGE_TYPE = "Observed Branch";
    private static final String VISITED_BRANCH_EDGE_TYPE = "Visited Observed Branch";
    private static final String THREAD_CREATE_FUNCTION_NAME = "gs_thread_create";
    private static final String SCALL_YIELD_FUNCTION_NAME = "SCALLYield";
    private static final String[] EXCLUDED_FUNCTION_PREFIXES = {
        "cmd_",
        "gs_vmem_cmd",
        "gs_checkout_cmd",
        "gs_log_cmd",
        "gs_command_cmd",
        "adc_read",
        "hmc5843_test_single",
        "hmc5843_loop",
        "hmc5843_get_info",
        "hmc5843_test_bias",
        "free_intern",
        "free_extern",
        "cpu_reset_handler",
        "ps_handler",
        "peek_handler",
        "poke_handler",
    };
    private static final long INTERRUPT_ENTRY_ADDRESS = 0x8005ab20L;
    private static final long INTERRUPT_EXIT_ADDRESS = 0x8005ab42L;
    private static final int HEADER_HEIGHT = 60;
    private static final int MARGIN_X = 60;
    private static final int MARGIN_Y = 40;
    private static final int LAYER_GAP = 160;
    private static final int ROW_GAP = 18;
    private static final int GROUP_GAP = 14;
    private static final int BAND_GAP = 28;
    private static final int BOX_WIDTH = 130;
    private static final int BOX_HEIGHT = 18;
    private static final Color BACKGROUND_COLOR = new Color(0xf8, 0xfa, 0xfc);
    private static final Color TITLE_COLOR = new Color(0x1f, 0x29, 0x33);
    private static final Color META_COLOR = new Color(0x52, 0x60, 0x6d);
    private static final Color NODE_BORDER_COLOR = new Color(0x47, 0x55, 0x69);
    private static final Color EDGE_COLOR = new Color(0x94, 0xa3, 0xb8, 96);
    private static final Color INTRA_EDGE_COLOR = new Color(0x64, 0x74, 0x8b, 56);
    private static final Color DIM_EDGE_COLOR = new Color(0x94, 0xa3, 0xb8, 26);
    private static final Color DIM_INTRA_EDGE_COLOR = new Color(0x64, 0x74, 0x8b, 16);
    private static final Color VISITED_EDGE_COLOR = new Color(0x16, 0xa3, 0x4a, 152);
    private static final Color VISITED_INTRA_EDGE_COLOR = new Color(0x16, 0xa3, 0x4a, 96);
    private static final Color REACHABLE_EDGE_COLOR = new Color(0xf0, 0x80, 0x80, 164);
    private static final Color REACHABLE_INTRA_EDGE_COLOR = new Color(0xf0, 0x80, 0x80, 104);
    private static final Color BRANCH_EDGE_COLOR = new Color(0xdc, 0x26, 0x26, 168);
    private static final Color BRANCH_INTRA_EDGE_COLOR = new Color(0xdc, 0x26, 0x26, 112);
    private static final Color VISITED_BRANCH_EDGE_COLOR = new Color(0xf5, 0x9e, 0x0b, 176);
    private static final Color VISITED_BRANCH_INTRA_EDGE_COLOR = new Color(0xf5, 0x9e, 0x0b, 120);
    private static final Font TITLE_FONT = new Font("SansSerif", Font.BOLD, 18);
    private static final Font META_FONT = new Font("SansSerif", Font.PLAIN, 10);
    private static final Font LABEL_FONT = new Font("SansSerif", Font.PLAIN, 9);
    private static final Font BAND_FONT = new Font("SansSerif", Font.BOLD, 11);
    private static final DecimalFormat COVERAGE_FORMAT = new DecimalFormat("0.0");
    private static final String[] ENTRYPOINT_COLOR_PALETTE = {
        "#eb1717",
        "#dd4400",
        "#b86e00",
        "#758d00",
        "#00a102",
        "#00a780",
        "#009ec8",
        "#0088f8",
        "#476bff",
        "#954ef5",
        "#c433c3",
        "#e2137e",
    };
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
    private int coveredStaticNodeCount;
    private int coveredStaticEdgeCount;
    private int coverableStaticNodeCount;
    private int coverableStaticEdgeCount;
    private int unresolvedVisitedAddressCount;
    private int reachableNodeCount;
    private int reachableEdgeCount;
    private final List<String> threadEntrySeedLog = new ArrayList<>();
    private final List<String> entrypointColorLog = new ArrayList<>();
    private final Map<String, String> reachableVertexColorOverrides = new HashMap<>();
    private final Map<String, String> reachableEdgeColorOverrides = new HashMap<>();
    private final Map<String, String> reachableVertexOwnerSeed = new HashMap<>();
    private final Map<String, Integer> reachableSeedOrder = new HashMap<>();
    private final Map<String, String> layoutVertexOwnerGroup = new HashMap<>();
    private final Map<String, Integer> layoutGroupOrder = new HashMap<>();
    private Function cachedThreadCreateFunction;
    private Function cachedScallYieldFunction;

    @Override
    protected void run() throws Exception {
        List<Function> functions = getAllFunctions();
        cachedThreadCreateFunction = findNamedFunction(functions, THREAD_CREATE_FUNCTION_NAME);
        cachedScallYieldFunction = findNamedFunction(functions, SCALL_YIELD_FUNCTION_NAME);
        LayoutGrouping cmdLayoutGrouping = buildCmdLayoutGrouping(functions);
        AttributedGraph staticGraph = createGraph("Static Call Graph");
        vertexCache.clear();
        buildCallGraph(staticGraph, functions);
        Set<String> coverageExcludedVertexIds = collectCoverageExcludedVertexIds(functions);
        Set<String> staticEdgeKeys = collectCoverableEdgeKeys(staticGraph, coverageExcludedVertexIds);
        coverableStaticNodeCount = countCoverableVertices(staticGraph, coverageExcludedVertexIds);
        coverableStaticEdgeCount = staticEdgeKeys.size();

        AttributedGraph reachableGraph = createGraph("Main-Reachable Call Graph");
        vertexCache.clear();
        buildCallGraph(reachableGraph, functions);
        highlightReachableFromMain(reachableGraph, functions);
        LayoutGrouping staticWithCmdGrouping = buildCmdAppendedGrouping(
            staticGraph,
            reachableVertexOwnerSeed,
            reachableSeedOrder,
            cmdLayoutGrouping
        );
        GraphLayout staticLayout = buildLayout(
            staticGraph,
            true,
            staticWithCmdGrouping.vertexOwnerGroup,
            staticWithCmdGrouping.groupOrder
        );
        Path reachableDotPath = writeDotFile(
            reachableGraph,
            "callgraph_reachable.dot",
            reachableVertexColorOverrides,
            reachableEdgeColorOverrides
        );
        Path reachablePngPath = writePngFile(
            reachableGraph,
            "Main-Reachable Call Graph",
            "nodes=" + reachableGraph.getVertexCount() +
            " edges=" + reachableGraph.getEdgeCount() +
            " reachableNodes=" + reachableNodeCount +
            " reachableEdges=" + reachableEdgeCount,
            "callgraph_reachable.png",
            true,
            true,
            true,
            reachableVertexOwnerSeed,
            reachableSeedOrder,
            reachableVertexColorOverrides,
            reachableEdgeColorOverrides,
            null
        );
        Path staticDotPath = writeDotFile(
            staticGraph,
            "callgraph_static.dot",
            reachableVertexColorOverrides,
            reachableEdgeColorOverrides
        );
        Path staticPngPath = writePngFile(
            staticGraph,
            "Static Call Graph",
            "nodes=" + staticGraph.getVertexCount() +
            " edges=" + staticGraph.getEdgeCount(),
            "callgraph_static.png",
            true,
            false,
            true,
            staticWithCmdGrouping.vertexOwnerGroup,
            staticWithCmdGrouping.groupOrder,
            reachableVertexColorOverrides,
            reachableEdgeColorOverrides,
            staticLayout
        );

        AttributedGraph graph = createGraph("Call Graph");
        vertexCache.clear();
        List<TraceEntry> traceEntries = loadInstructionTraceEntries();
        buildCallGraph(graph, functions);
        highlightObservedBranches(graph, traceEntries);
        highlightVisitedExecution(graph, traceEntries, staticEdgeKeys);
        Map<String, String> dynamicVertexColorOverrides = buildDynamicVertexColorOverrides(graph);
        Map<String, String> dynamicEdgeColorOverrides = buildDynamicEdgeColorOverrides(graph);
        Path dotPath = writeDotFile(
            graph,
            "callgraph_dynamic.dot",
            dynamicVertexColorOverrides,
            dynamicEdgeColorOverrides
        );
        LayoutGrouping dynamicWithCmdGrouping = buildCmdAppendedGrouping(
            graph,
            reachableVertexOwnerSeed,
            reachableSeedOrder,
            cmdLayoutGrouping
        );
        Path pngPath = writePngFile(
            graph,
            "Call Graph",
            "nodes=" + graph.getVertexCount() +
            " edges=" + graph.getEdgeCount() +
            " layers=" + staticLayout.layerCount +
            " redBranches=" + observedBranchEdgeCount +
            " greenVisited=" + visitedEdgeCount +
            "\nstaticNodeCoverage=" + buildCoverageSummary(coveredStaticNodeCount, coverableStaticNodeCount) +
            " staticEdgeCoverage=" + buildCoverageSummary(coveredStaticEdgeCount, coverableStaticEdgeCount),
            "callgraph_dynamic.png",
            true,
            false,
            true,
            dynamicWithCmdGrouping.vertexOwnerGroup,
            dynamicWithCmdGrouping.groupOrder,
            dynamicVertexColorOverrides,
            dynamicEdgeColorOverrides,
            staticLayout
        );

        println("Program: " + currentProgram.getName());
        println("Functions in graph: " + staticGraph.getVertexCount());
        println("Static graph edges total: " + staticGraph.getEdgeCount());
        println("Static DOT export: " + staticDotPath.toAbsolutePath());
        println("Static PNG export: " + staticPngPath.toAbsolutePath());
        println("Reachable nodes highlighted: " + reachableNodeCount);
        println("Reachable edges highlighted: " + reachableEdgeCount);
        println("Reachable DOT export: " + reachableDotPath.toAbsolutePath());
        println("Reachable PNG export: " + reachablePngPath.toAbsolutePath());
        println("Thread entry seeds found: " + threadEntrySeedLog.size());
        for (String threadEntryRecord : threadEntrySeedLog) {
            println("Thread entry seed: " + threadEntryRecord);
        }
        for (String entrypointColorRecord : entrypointColorLog) {
            println("Entrypoint color: " + entrypointColorRecord);
        }
        println("Dynamic graph edges total: " + graph.getEdgeCount());
        println("Observed branch entries: " + observedBranchEntryCount);
        println("Observed branch edges highlighted: " + observedBranchEdgeCount);
        println("Observed branch entries unresolved: " + unresolvedBranchEntryCount);
        println("Visited nodes highlighted: " + visitedNodeCount);
        println("Visited edges highlighted: " + visitedEdgeCount);
        println(
            "Static nodes covered: " +
            buildCoverageSummary(coveredStaticNodeCount, coverableStaticNodeCount)
        );
        println(
            "Static edges covered: " +
            buildCoverageSummary(coveredStaticEdgeCount, coverableStaticEdgeCount)
        );
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
        FunctionManager functionManager = currentProgram.getFunctionManager();

        for (Function function : functions) {
            monitor.checkCancelled();
            getOrCreateVertex(graph, function);
        }

        for (Function caller : functions) {
            monitor.checkCancelled();

            AttributedVertex callerVertex = getOrCreateVertex(graph, caller);
            for (Function callee : getStaticSuccessorFunctions(caller, functionManager)) {
                monitor.checkCancelled();
                AttributedVertex calleeVertex = getOrCreateVertex(graph, callee);
                addEdgeIfAbsent(graph, callerVertex, calleeVertex);
            }
        }
    }

    private List<Function> getStaticSuccessorFunctions(Function caller, FunctionManager functionManager) {
        Set<Function> successors = new TreeSet<>(FUNCTION_ORDER);
        successors.addAll(caller.getCalledFunctions(monitor));
        successors.addAll(getInterFunctionFlowSuccessors(caller, functionManager));
        if (cachedScallYieldFunction != null && functionContainsMnemonic(caller, "SCALL")) {
            successors.add(cachedScallYieldFunction);
        }
        return new ArrayList<>(successors);
    }

    private boolean functionContainsMnemonic(Function function, String mnemonic) {
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            if (mnemonic.equals(instruction.getMnemonicString())) {
                return true;
            }
        }
        return false;
    }

    private Set<Function> getInterFunctionFlowSuccessors(
        Function caller,
        FunctionManager functionManager
    ) {
        Set<Function> successors = new TreeSet<>(FUNCTION_ORDER);
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(caller.getBody(), true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            addSuccessorIfDifferentFunction(
                successors,
                caller,
                functionManager,
                instruction.getFallThrough()
            );

            for (var flow : instruction.getFlows()) {
                addSuccessorIfDifferentFunction(successors, caller, functionManager, flow);
            }
        }

        return successors;
    }

    private void addSuccessorIfDifferentFunction(
        Set<Function> successors,
        Function caller,
        FunctionManager functionManager,
        ghidra.program.model.address.Address target
    ) {
        if (target == null) {
            return;
        }

        Function callee = functionManager.getFunctionContaining(target);
        if (callee == null || callee.getEntryPoint().equals(caller.getEntryPoint())) {
            return;
        }

        successors.add(callee);
    }

    private AttributedEdge addEdgeIfAbsent(
        AttributedGraph graph,
        AttributedVertex sourceVertex,
        AttributedVertex targetVertex
    ) {
        String edgeKey = buildEdgeKey(sourceVertex, targetVertex);
        for (AttributedEdge edge : graph.edgeSet()) {
            AttributedVertex existingSource = graph.getEdgeSource(edge);
            AttributedVertex existingTarget = graph.getEdgeTarget(edge);
            if (existingSource != null &&
                existingTarget != null &&
                edgeKey.equals(buildEdgeKey(existingSource, existingTarget))) {
                return edge;
            }
        }

        return graph.addEdge(sourceVertex, targetVertex);
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
            .vertex(REACHABLE_INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0xf6, 0xa1, 0x9a))
            .vertex(REACHABLE_EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xf6, 0xa1, 0x9a))
            .vertex(BRANCH_INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0xfe, 0xca, 0xca))
            .vertex(BRANCH_EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xfecaca))
            .vertex(VISITED_BRANCH_INTERNAL_VERTEX_TYPE, VertexShape.RECTANGLE, new Color(0xfd, 0xba, 0x74))
            .vertex(VISITED_BRANCH_EXTERNAL_VERTEX_TYPE, VertexShape.ELLIPSE, new Color(0xfd, 0xba, 0x74))
            .edge(VISITED_EDGE_TYPE, new Color(0x16, 0xa3, 0x4a))
            .edge(REACHABLE_EDGE_TYPE, new Color(0xf0, 0x80, 0x80))
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
        String filename,
        boolean includeBaseEdges,
        boolean dimBaseEdges,
        boolean groupByOwnershipBand,
        Map<String, String> vertexOwnerGroup,
        Map<String, Integer> groupOrder,
        Map<String, String> vertexColorOverrides,
        Map<String, String> edgeColorOverrides,
        GraphLayout precomputedLayout
    ) throws IOException {
        GraphLayout layout = precomputedLayout != null
            ? precomputedLayout
            : buildLayout(graph, groupByOwnershipBand, vertexOwnerGroup, groupOrder);
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
            drawMetadata(graphics, metadata, 24, 46);

            drawEdges(graphics, graph, layout, includeBaseEdges, dimBaseEdges, edgeColorOverrides);
            drawBandLabels(graphics, layout);
            drawNodes(graphics, layout, vertexColorOverrides);
        } finally {
            graphics.dispose();
        }

        Path outPath = getOutputPath(filename);
        Files.createDirectories(outPath.getParent());
        ImageIO.write(image, "png", outPath.toFile());
        return outPath;
    }

    private void drawBandLabels(Graphics2D graphics, GraphLayout layout) {
        if (layout.bandLabels.isEmpty()) {
            return;
        }
        graphics.setFont(BAND_FONT);
        graphics.setColor(META_COLOR);
        for (BandLabel bandLabel : layout.bandLabels) {
            graphics.drawString(bandLabel.text, 12, bandLabel.y);
        }
    }

    private void drawMetadata(Graphics2D graphics, String metadata, int x, int y) {
        String[] lines = metadata.split("\\n", -1);
        for (int i = 0; i < lines.length; i++) {
            graphics.drawString(lines[i], x, y + (i * 12));
        }
    }

    private void drawEdges(
        Graphics2D graphics,
        AttributedGraph graph,
        GraphLayout layout,
        boolean includeBaseEdges,
        boolean dimBaseEdges,
        Map<String, String> edgeColorOverrides
    ) {
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

            if (!includeBaseEdges && !isHighlightedEdge(edge)) {
                continue;
            }

            String edgeKey = buildEdgeKey(sourceVertex, targetVertex);
            String overrideColor = edgeColorOverrides == null ? null : edgeColorOverrides.get(edgeKey);
            if (overrideColor != null) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(
                    applyAlpha(parseHexColor(overrideColor), source.layer == target.layer ? 116 : 176)
                );
                graphics.draw(curve);
                continue;
            }

            if (isVisitedBranchEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? VISITED_BRANCH_INTRA_EDGE_COLOR : VISITED_BRANCH_EDGE_COLOR);
            } else if (isObservedBranchEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? BRANCH_INTRA_EDGE_COLOR : BRANCH_EDGE_COLOR);
            } else if (isReachableEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? REACHABLE_INTRA_EDGE_COLOR : REACHABLE_EDGE_COLOR);
            } else if (isVisitedEdge(edge)) {
                graphics.setStroke(source.layer == target.layer ? intraLayerStroke : interLayerStroke);
                graphics.setColor(source.layer == target.layer ? VISITED_INTRA_EDGE_COLOR : VISITED_EDGE_COLOR);
            } else if (source.layer == target.layer) {
                graphics.setStroke(intraLayerStroke);
                graphics.setColor(dimBaseEdges ? DIM_INTRA_EDGE_COLOR : INTRA_EDGE_COLOR);
            } else {
                graphics.setStroke(interLayerStroke);
                graphics.setColor(dimBaseEdges ? DIM_EDGE_COLOR : EDGE_COLOR);
            }
            graphics.draw(curve);
        }
    }

    private void drawNodes(
        Graphics2D graphics,
        GraphLayout layout,
        Map<String, String> vertexColorOverrides
    ) {
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

            String fillColor = nodeLayout.fillColor;
            if (vertexColorOverrides != null && vertexColorOverrides.containsKey(nodeLayout.vertex.getId())) {
                fillColor = vertexColorOverrides.get(nodeLayout.vertex.getId());
            }
            graphics.setColor(parseHexColor(fillColor));
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

    private GraphLayout buildLayout(
        AttributedGraph graph,
        boolean groupByOwnershipBand,
        Map<String, String> vertexOwnerGroup,
        Map<String, Integer> groupOrder
    ) {
        layoutVertexOwnerGroup.clear();
        layoutGroupOrder.clear();
        if (vertexOwnerGroup != null) {
            layoutVertexOwnerGroup.putAll(vertexOwnerGroup);
        }
        if (groupOrder != null) {
            layoutGroupOrder.putAll(groupOrder);
        }
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
            componentVertices.sort(this::compareVerticesForLayerLayout);
            List<AttributedVertex> layerVertices = layerMap.computeIfAbsent(
                componentLayers.get(i),
                ignored -> new ArrayList<>()
            );
            layerVertices.addAll(componentVertices);
        }
        for (List<AttributedVertex> layerVertices : layerMap.values()) {
            layerVertices.sort(this::compareVerticesForLayerLayout);
        }

        if (groupByOwnershipBand) {
            return buildOwnershipBandLayout(layerMap);
        }

        List<List<AttributedVertex>> orderedLayers = new ArrayList<>(layerMap.values());
        int maxLayerSize = 1;
        for (List<AttributedVertex> layerVertices : orderedLayers) {
            maxLayerSize = Math.max(maxLayerSize, computeLayerHeightUnits(layerVertices));
        }

        int bodyHeight = BOX_HEIGHT + ((maxLayerSize - 1) * ROW_GAP);
        int width = (MARGIN_X * 2) + BOX_WIDTH + (Math.max(1, orderedLayers.size()) - 1) * LAYER_GAP;
        int height = HEADER_HEIGHT + (MARGIN_Y * 2) + bodyHeight;

        List<NodeLayout> nodeLayouts = new ArrayList<>();
        Map<String, NodeLayout> positions = new HashMap<>();
        List<BandLabel> bandLabels = new ArrayList<>();

        int layerIndex = 0;
        for (List<AttributedVertex> layerVertices : orderedLayers) {
            int totalLayerHeight = computeRenderedLayerHeight(layerVertices);
            int x = MARGIN_X + (layerIndex * LAYER_GAP);
            int yStart = HEADER_HEIGHT + MARGIN_Y + ((bodyHeight - totalLayerHeight) / 2);
            int currentY = yStart;
            String previousGroupKey = null;

            for (int rowIndex = 0; rowIndex < layerVertices.size(); rowIndex++) {
                AttributedVertex vertex = layerVertices.get(rowIndex);
                String currentGroupKey = getVertexOwnershipGroupKey(vertex);
                if (previousGroupKey != null && !previousGroupKey.equals(currentGroupKey)) {
                    currentY += GROUP_GAP;
                }
                NodeLayout nodeLayout = new NodeLayout(
                    vertex,
                    layerIndex,
                    x,
                    currentY,
                    getVertexFillColor(vertex)
                );
                nodeLayouts.add(nodeLayout);
                positions.put(vertex.getId(), nodeLayout);
                currentY += ROW_GAP;
                previousGroupKey = currentGroupKey;
            }
            layerIndex++;
        }

        nodeLayouts.sort((left, right) -> {
            if (left.layer != right.layer) {
                return Integer.compare(left.layer, right.layer);
            }
            return compareVerticesForLayerLayout(left.vertex, right.vertex);
        });

        return new GraphLayout(width, height, orderedLayers.size(), nodeLayouts, positions, new ArrayList<>());
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
            if (isExcludedDynamicTransition(previousEntry, currentEntry)) {
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

    private void highlightVisitedExecution(
        AttributedGraph graph,
        List<TraceEntry> traceEntries,
        Set<String> staticEdgeKeys
    ) throws Exception {
        visitedNodeCount = 0;
        visitedEdgeCount = 0;
        coveredStaticNodeCount = 0;
        coveredStaticEdgeCount = 0;
        unresolvedVisitedAddressCount = 0;
        if (traceEntries.isEmpty()) {
            return;
        }

        Set<String> visitedVertices = new TreeSet<>();
        Set<String> visitedEdges = new TreeSet<>();
        Set<String> coveredStaticVertices = new TreeSet<>();
        Set<String> coveredStaticEdges = new TreeSet<>();
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
            if (!shouldExcludeVertexFromCoverage(currentVertex)) {
                coveredStaticVertices.add(currentVertex.getId());
            }

            if (previousVertex != null &&
                !previousVertex.getId().equals(currentVertex.getId()) &&
                !isExcludedDynamicTransition(previousEntry, currentEntry)) {
                Instruction previousInstruction = getInstructionAt(toAddr(previousEntry.addressValue));
                if (previousInstruction != null && !previousInstruction.getFlowType().isTerminal()) {
                    AttributedEdge edge = graph.addEdge(previousVertex, currentVertex);
                    markVisitedEdge(edge);
                    String edgeKey = buildEdgeKey(previousVertex, currentVertex);
                    visitedEdges.add(edgeKey);
                    if (staticEdgeKeys.contains(edgeKey) &&
                        !shouldExcludeVertexFromCoverage(previousVertex) &&
                        !shouldExcludeVertexFromCoverage(currentVertex)) {
                        coveredStaticEdges.add(edgeKey);
                    }
                }
            }

            previousVertex = currentVertex;
            previousEntry = currentEntry;
        }

        visitedNodeCount = visitedVertices.size();
        visitedEdgeCount = visitedEdges.size();
        coveredStaticNodeCount = coveredStaticVertices.size();
        coveredStaticEdgeCount = coveredStaticEdges.size();
    }

    private Set<String> collectEdgeKeys(AttributedGraph graph) {
        Set<String> edgeKeys = new TreeSet<>();
        for (AttributedEdge edge : graph.edgeSet()) {
            AttributedVertex sourceVertex = graph.getEdgeSource(edge);
            AttributedVertex targetVertex = graph.getEdgeTarget(edge);
            if (sourceVertex == null || targetVertex == null) {
                continue;
            }
            edgeKeys.add(buildEdgeKey(sourceVertex, targetVertex));
        }
        return edgeKeys;
    }

    private Set<String> collectCoverableEdgeKeys(AttributedGraph graph, Set<String> excludedVertexIds) {
        Set<String> edgeKeys = new TreeSet<>();
        for (AttributedEdge edge : graph.edgeSet()) {
            AttributedVertex sourceVertex = graph.getEdgeSource(edge);
            AttributedVertex targetVertex = graph.getEdgeTarget(edge);
            if (sourceVertex == null || targetVertex == null) {
                continue;
            }
            if (excludedVertexIds.contains(sourceVertex.getId()) || excludedVertexIds.contains(targetVertex.getId())) {
                continue;
            }
            edgeKeys.add(buildEdgeKey(sourceVertex, targetVertex));
        }
        return edgeKeys;
    }

    private int countCoverableVertices(AttributedGraph graph, Set<String> excludedVertexIds) {
        int count = 0;
        for (AttributedVertex vertex : graph.vertexSet()) {
            if (!excludedVertexIds.contains(vertex.getId())) {
                count++;
            }
        }
        return count;
    }

    private Set<String> collectCoverageExcludedVertexIds(List<Function> functions) {
        Set<String> excludedVertexIds = new TreeSet<>();
        LayoutGrouping cmdGrouping = buildCmdLayoutGrouping(functions);
        for (Map.Entry<String, String> entry : cmdGrouping.vertexOwnerGroup.entrySet()) {
            if ("~cmd".equals(entry.getValue())) {
                excludedVertexIds.add(entry.getKey());
            }
        }
        for (Function function : functions) {
            if (shouldExcludeFromCoverage(function)) {
                excludedVertexIds.add(function.getEntryPoint().toString());
            }
        }
        return excludedVertexIds;
    }

    private boolean shouldExcludeVertexFromCoverage(AttributedVertex vertex) {
        if (vertex == null) {
            return false;
        }
        Function function = resolveFunctionByVertexId(vertex.getId());
        if (function == null) {
            return false;
        }
        return shouldExcludeFromCoverage(function);
    }

    private Function resolveFunctionByVertexId(String vertexId) {
        if (vertexId == null || vertexId.startsWith("addr:")) {
            return null;
        }
        try {
            return currentProgram.getFunctionManager().getFunctionAt(toAddr(vertexId));
        } catch (Exception ignored) {
            return null;
        }
    }

    private String buildEdgeKey(AttributedVertex sourceVertex, AttributedVertex targetVertex) {
        return sourceVertex.getId() + "->" + targetVertex.getId();
    }

    private String buildCoverageSummary(int coveredEdges, int totalEdges) {
        if (totalEdges <= 0) {
            return coveredEdges + "/0 (0.0%)";
        }

        double coveragePercent = (100.0 * coveredEdges) / totalEdges;
        return coveredEdges + "/" + totalEdges + " (" + COVERAGE_FORMAT.format(coveragePercent) + "%)";
    }

    private void highlightReachableFromMain(AttributedGraph graph, List<Function> functions) throws Exception {
        reachableNodeCount = 0;
        reachableEdgeCount = 0;
        threadEntrySeedLog.clear();
        entrypointColorLog.clear();
        reachableVertexColorOverrides.clear();
        reachableEdgeColorOverrides.clear();
        reachableVertexOwnerSeed.clear();
        reachableSeedOrder.clear();

        Function mainFunction = findMainFunction(functions);
        if (mainFunction == null) {
            println("No function named 'main' found; reachable graph was generated without highlights.");
            return;
        }

        Set<String> reachableVertices = new TreeSet<>();
        Set<String> reachableEdges = new TreeSet<>();
        List<Function> worklist = new ArrayList<>();
        Set<String> queuedFunctionIds = new TreeSet<>();
        Map<String, Function> entrySeedFunctions = new HashMap<>();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Function threadCreateFunction = cachedThreadCreateFunction;
        worklist.add(mainFunction);
        queuedFunctionIds.add(mainFunction.getEntryPoint().toString());
        entrySeedFunctions.put(mainFunction.getEntryPoint().toString(), mainFunction);

        DecompInterface decompiler = new DecompInterface();
        boolean decompilerReady = false;
        try {
            decompiler.setOptions(new DecompileOptions());
            decompilerReady = decompiler.openProgram(currentProgram);
            if (!decompilerReady) {
                println("Decompiler unavailable for thread entry discovery: " + decompiler.getLastMessage());
            }

            while (!worklist.isEmpty()) {
                monitor.checkCancelled();

                Function current = worklist.remove(worklist.size() - 1);
                AttributedVertex currentVertex = getOrCreateVertex(graph, current);
                markReachableVertex(currentVertex);
                reachableVertices.add(currentVertex.getId());

                for (Function callee : getStaticSuccessorFunctions(current, functionManager)) {
                    monitor.checkCancelled();

                    AttributedVertex calleeVertex = getOrCreateVertex(graph, callee);
                    markReachableVertex(calleeVertex);
                    reachableVertices.add(calleeVertex.getId());

                    AttributedEdge edge = addEdgeIfAbsent(graph, currentVertex, calleeVertex);
                    markReachableEdge(edge);
                    reachableEdges.add(buildEdgeKey(currentVertex, calleeVertex));

                    String calleeId = callee.getEntryPoint().toString();
                    if (queuedFunctionIds.add(calleeId)) {
                        worklist.add(callee);
                    }
                }

                for (Function threadEntry : findThreadEntryFunctions(
                    current,
                    threadCreateFunction,
                    functionManager,
                    decompiler,
                    decompilerReady
                )) {
                    monitor.checkCancelled();

                    logThreadEntrySeed(current, threadEntry);

                    String threadId = threadEntry.getEntryPoint().toString();
                    entrySeedFunctions.put(threadId, threadEntry);
                    if (queuedFunctionIds.add(threadId)) {
                        worklist.add(threadEntry);
                    }
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        reachableNodeCount = reachableVertices.size();
        reachableEdgeCount = reachableEdges.size();
        applyEntrypointExclusiveColors(graph, entrySeedFunctions, functionManager);
    }

    private void applyEntrypointExclusiveColors(
        AttributedGraph graph,
        Map<String, Function> entrySeedFunctions,
        FunctionManager functionManager
    ) throws Exception {
        Map<String, String> entrySeedColors = assignEntrypointColors(entrySeedFunctions);
        Map<String, Set<String>> seedToVertices = new HashMap<>();
        Map<String, Set<String>> seedToEdges = new HashMap<>();

        for (Map.Entry<String, Function> entry : entrySeedFunctions.entrySet()) {
            ReachabilitySet reachability = collectReachabilityFromSeed(entry.getValue(), functionManager);
            seedToVertices.put(entry.getKey(), reachability.vertexIds);
            seedToEdges.put(entry.getKey(), reachability.edgeKeys);
        }

        Map<String, Integer> vertexCounts = new HashMap<>();
        Map<String, Integer> edgeCounts = new HashMap<>();
        for (Set<String> vertexIds : seedToVertices.values()) {
            for (String vertexId : vertexIds) {
                vertexCounts.put(vertexId, vertexCounts.getOrDefault(vertexId, 0) + 1);
            }
        }
        for (Set<String> edgeKeys : seedToEdges.values()) {
            for (String edgeKey : edgeKeys) {
                edgeCounts.put(edgeKey, edgeCounts.getOrDefault(edgeKey, 0) + 1);
            }
        }

        for (Map.Entry<String, Function> entry : entrySeedFunctions.entrySet()) {
            String seedId = entry.getKey();
            String seedColor = entrySeedColors.get(seedId);
            if (seedColor == null) {
                continue;
            }

            reachableVertexColorOverrides.put(seedId, seedColor);
            reachableVertexOwnerSeed.put(seedId, seedId);
            for (String vertexId : seedToVertices.getOrDefault(seedId, Set.of())) {
                if (vertexCounts.getOrDefault(vertexId, 0) == 1) {
                    reachableVertexColorOverrides.put(vertexId, seedColor);
                    reachableVertexOwnerSeed.put(vertexId, seedId);
                }
            }
            for (String edgeKey : seedToEdges.getOrDefault(seedId, Set.of())) {
                if (edgeCounts.getOrDefault(edgeKey, 0) == 1) {
                    reachableEdgeColorOverrides.put(edgeKey, seedColor);
                }
            }
        }

        Set<String> reachableUnion = new TreeSet<>();
        for (Set<String> vertexIds : seedToVertices.values()) {
            reachableUnion.addAll(vertexIds);
        }
        for (AttributedVertex vertex : graph.vertexSet()) {
            String vertexId = vertex.getId();
            if (reachableVertexOwnerSeed.containsKey(vertexId)) {
                continue;
            }
            if (reachableUnion.contains(vertexId)) {
                reachableVertexOwnerSeed.put(vertexId, "~shared");
            } else {
                reachableVertexOwnerSeed.put(vertexId, "~unreachable");
            }
        }
    }

    private Map<String, String> assignEntrypointColors(Map<String, Function> entrySeedFunctions) {
        Map<String, String> colors = new HashMap<>();
        List<Function> orderedSeeds = sortFunctions(entrySeedFunctions.values());
        Function mainFunction = findMainFunction(orderedSeeds);
        int paletteIndex = 0;

        if (mainFunction != null) {
            String color = ENTRYPOINT_COLOR_PALETTE[paletteIndex % ENTRYPOINT_COLOR_PALETTE.length];
            colors.put(mainFunction.getEntryPoint().toString(), color);
            reachableSeedOrder.put(mainFunction.getEntryPoint().toString(), paletteIndex);
            entrypointColorLog.add(
                mainFunction.getName() + " @ " + mainFunction.getEntryPoint() + " = " + color
            );
            paletteIndex++;
        }

        for (Function function : orderedSeeds) {
            String seedId = function.getEntryPoint().toString();
            if (colors.containsKey(seedId)) {
                continue;
            }
            String color = ENTRYPOINT_COLOR_PALETTE[paletteIndex % ENTRYPOINT_COLOR_PALETTE.length];
            colors.put(seedId, color);
            reachableSeedOrder.put(seedId, paletteIndex);
            entrypointColorLog.add(function.getName() + " @ " + function.getEntryPoint() + " = " + color);
            paletteIndex++;
        }

        return colors;
    }

    private LayoutGrouping buildCmdLayoutGrouping(List<Function> functions) {
        LayoutGrouping grouping = new LayoutGrouping();
        grouping.groupOrder.put("~normal", 0);
        grouping.groupOrder.put("~cmd", 1);

        FunctionManager functionManager = currentProgram.getFunctionManager();
        Map<String, Set<String>> callersByFunctionId = new HashMap<>();
        Map<String, Function> functionsById = new HashMap<>();
        for (Function function : functions) {
            String functionId = function.getEntryPoint().toString();
            functionsById.put(functionId, function);
            callersByFunctionId.put(functionId, new TreeSet<>());
        }

        for (Function caller : functions) {
            String callerId = caller.getEntryPoint().toString();
            for (Function callee : getStaticSuccessorFunctions(caller, functionManager)) {
                String calleeId = callee.getEntryPoint().toString();
                callersByFunctionId.computeIfAbsent(calleeId, ignored -> new TreeSet<>()).add(callerId);
            }
        }

        Set<String> cmdClosure = new TreeSet<>();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (Function function : functions) {
                String functionId = function.getEntryPoint().toString();
                if (cmdClosure.contains(functionId)) {
                    continue;
                }

                if (isCmdSeedFunction(function)) {
                    cmdClosure.add(functionId);
                    changed = true;
                    continue;
                }

                Set<String> callers = callersByFunctionId.getOrDefault(functionId, Set.of());
                if (!callers.isEmpty() && cmdClosure.containsAll(callers)) {
                    cmdClosure.add(functionId);
                    changed = true;
                }
            }
        }

        for (Function function : functions) {
            String functionId = function.getEntryPoint().toString();
            grouping.vertexOwnerGroup.put(functionId, cmdClosure.contains(functionId) ? "~cmd" : "~normal");
        }
        return grouping;
    }

    private boolean isCmdSeedFunction(Function function) {
        if (shouldExcludeFromCmdBand(function)) {
            return false;
        }
        String functionName = function.getName();
        for (String prefix : EXCLUDED_FUNCTION_PREFIXES) {
            if (functionName.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean shouldExcludeFromCoverage(Function function) {
        return shouldExcludeFromCmdBand(function);
    }

    private boolean shouldExcludeFromCmdBand(Function function) {
        String functionName = function.getName();
        String functionId = function.getEntryPoint().toString();

        // Add future opt-out rules here when a cmd_-prefixed function should stay out of the cmd band.
        return false;
    }

    private LayoutGrouping buildCmdAppendedGrouping(
        AttributedGraph graph,
        Map<String, String> baseOwnerGroup,
        Map<String, Integer> baseOrder,
        LayoutGrouping cmdGrouping
    ) {
        LayoutGrouping grouping = new LayoutGrouping();
        int maxOrder = -1;
        for (Integer order : baseOrder.values()) {
            if (order != null) {
                maxOrder = Math.max(maxOrder, order);
            }
        }

        grouping.groupOrder.putAll(baseOrder);
        if (!grouping.groupOrder.containsKey("~shared")) {
            grouping.groupOrder.put("~shared", maxOrder + 1);
            maxOrder++;
        }
        if (!grouping.groupOrder.containsKey("~unreachable")) {
            grouping.groupOrder.put("~unreachable", maxOrder + 1);
            maxOrder++;
        }
        grouping.groupOrder.put("~cmd", maxOrder + 1);

        for (AttributedVertex vertex : graph.vertexSet()) {
            String vertexId = vertex.getId();
            String owner = baseOwnerGroup.getOrDefault(vertexId, "~unreachable");
            if ("~cmd".equals(cmdGrouping.vertexOwnerGroup.get(vertexId))) {
                owner = "~cmd";
            }
            grouping.vertexOwnerGroup.put(vertexId, owner);
        }
        return grouping;
    }

    private ReachabilitySet collectReachabilityFromSeed(
        Function seedFunction,
        FunctionManager functionManager
    ) throws Exception {
        ReachabilitySet reachability = new ReachabilitySet();
        if (seedFunction == null) {
            return reachability;
        }

        List<Function> worklist = new ArrayList<>();
        Set<String> queuedFunctionIds = new TreeSet<>();
        worklist.add(seedFunction);
        queuedFunctionIds.add(seedFunction.getEntryPoint().toString());

        while (!worklist.isEmpty()) {
            monitor.checkCancelled();

            Function current = worklist.remove(worklist.size() - 1);
            String currentId = current.getEntryPoint().toString();
            reachability.vertexIds.add(currentId);

            for (Function successor : getStaticSuccessorFunctions(current, functionManager)) {
                String successorId = successor.getEntryPoint().toString();
                reachability.vertexIds.add(successorId);
                reachability.edgeKeys.add(currentId + "->" + successorId);
                if (queuedFunctionIds.add(successorId)) {
                    worklist.add(successor);
                }
            }
        }

        return reachability;
    }

    private void logThreadEntrySeed(Function caller, Function threadEntry) {
        String record = caller.getName() +
            " @ " + caller.getEntryPoint() +
            " -> " +
            threadEntry.getName() +
            " @ " + threadEntry.getEntryPoint();
        if (!threadEntrySeedLog.contains(record)) {
            threadEntrySeedLog.add(record);
        }
    }

    private Function findMainFunction(List<Function> functions) {
        Function fallback = null;
        for (Function function : functions) {
            if (!"main".equals(function.getName())) {
                continue;
            }

            if (!function.isExternal() && !function.isThunk()) {
                return function;
            }
            if (fallback == null) {
                fallback = function;
            }
        }
        return fallback;
    }

    private Function findNamedFunction(List<Function> functions, String name) {
        Function fallback = null;
        for (Function function : functions) {
            if (!name.equals(function.getName())) {
                continue;
            }
            if (!function.isExternal() && !function.isThunk()) {
                return function;
            }
            if (fallback == null) {
                fallback = function;
            }
        }
        return fallback;
    }

    private List<Function> findThreadEntryFunctions(
        Function caller,
        Function threadCreateFunction,
        FunctionManager functionManager,
        DecompInterface decompiler,
        boolean decompilerReady
    ) {
        List<Function> entryFunctions = new ArrayList<>();
        if (caller == null || threadCreateFunction == null || !decompilerReady) {
            return entryFunctions;
        }

        DecompileResults results = decompiler.decompileFunction(caller, 30, monitor);
        if (results == null || !results.decompileCompleted()) {
            return entryFunctions;
        }

        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null || highFunction.getPcodeOps() == null) {
            return entryFunctions;
        }

        Set<String> seenEntryIds = new TreeSet<>();
        var opIterator = highFunction.getPcodeOps();
        while (opIterator.hasNext()) {
            PcodeOpAST callOp = opIterator.next();
            if (callOp.getOpcode() != PcodeOp.CALL || callOp.getNumInputs() < 3) {
                continue;
            }

            Function calledFunction = resolveCalledFunction(callOp.getInput(0), functionManager);
            if (calledFunction == null ||
                !threadCreateFunction.getEntryPoint().equals(calledFunction.getEntryPoint())) {
                continue;
            }

            Function entryFunction = resolveFunctionFromVarnode(
                callOp.getInput(2),
                functionManager,
                new TreeSet<>()
            );
            if (entryFunction == null) {
                continue;
            }

            if (seenEntryIds.add(entryFunction.getEntryPoint().toString())) {
                entryFunctions.add(entryFunction);
            }
        }

        return sortFunctions(entryFunctions);
    }

    private Function resolveCalledFunction(Varnode targetVarnode, FunctionManager functionManager) {
        if (targetVarnode == null) {
            return null;
        }

        if (targetVarnode.isConstant()) {
            return resolveFunctionByAddressValue(targetVarnode.getOffset(), functionManager);
        }

        if (targetVarnode.getAddress() != null) {
            Function function = functionManager.getFunctionAt(targetVarnode.getAddress());
            if (function != null) {
                return function;
            }
            return functionManager.getFunctionContaining(targetVarnode.getAddress());
        }

        return resolveFunctionFromVarnode(targetVarnode, functionManager, new TreeSet<>());
    }

    private Function resolveFunctionFromVarnode(
        Varnode varnode,
        FunctionManager functionManager,
        Set<String> seen
    ) {
        if (varnode == null || !seen.add(varnode.toString())) {
            return null;
        }

        if (varnode.isConstant()) {
            return resolveFunctionByAddressValue(varnode.getOffset(), functionManager);
        }

        if (varnode.getAddress() != null && varnode.getAddress().isMemoryAddress()) {
            Function function = functionManager.getFunctionAt(varnode.getAddress());
            if (function != null) {
                return function;
            }
            function = functionManager.getFunctionContaining(varnode.getAddress());
            if (function != null) {
                return function;
            }
        }

        PcodeOp definition = varnode.getDef();
        if (definition == null) {
            return null;
        }

        switch (definition.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INDIRECT:
                return resolveFunctionFromVarnode(definition.getInput(0), functionManager, seen);
            case PcodeOp.MULTIEQUAL:
                return resolveUniqueFunctionFromInputs(definition, functionManager, seen);
            case PcodeOp.PTRADD:
            case PcodeOp.PTRSUB:
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
                return resolveUniqueFunctionFromInputs(definition, functionManager, seen);
            default:
                return null;
        }
    }

    private Function resolveUniqueFunctionFromInputs(
        PcodeOp definition,
        FunctionManager functionManager,
        Set<String> seen
    ) {
        Function resolved = null;
        for (int i = 0; i < definition.getNumInputs(); i++) {
            Function candidate = resolveFunctionFromVarnode(definition.getInput(i), functionManager, seen);
            if (candidate == null) {
                continue;
            }
            if (resolved == null) {
                resolved = candidate;
                continue;
            }
            if (!resolved.getEntryPoint().equals(candidate.getEntryPoint())) {
                return null;
            }
        }
        return resolved;
    }

    private Function resolveFunctionByAddressValue(long addressValue, FunctionManager functionManager) {
        try {
            var address = toAddr(addressValue);
            Function function = functionManager.getFunctionAt(address);
            if (function != null) {
                return function;
            }
            return functionManager.getFunctionContaining(address);
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean isExcludedDynamicTransition(TraceEntry previousEntry, TraceEntry currentEntry) {
        return previousEntry.addressValue == INTERRUPT_EXIT_ADDRESS ||
            currentEntry.addressValue == INTERRUPT_ENTRY_ADDRESS;
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

    private void markReachableVertex(AttributedVertex vertex) {
        String vertexType = vertex.getVertexType();
        if (REACHABLE_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            REACHABLE_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return;
        }

        if (isExternalVertexType(vertexType)) {
            vertex.setVertexType(REACHABLE_EXTERNAL_VERTEX_TYPE);
        } else {
            vertex.setVertexType(REACHABLE_INTERNAL_VERTEX_TYPE);
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

    private void markReachableEdge(AttributedEdge edge) {
        if (!isHighlightedEdge(edge)) {
            edge.setEdgeType(REACHABLE_EDGE_TYPE);
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

    private Map<String, String> buildDynamicVertexColorOverrides(AttributedGraph graph) {
        Map<String, String> overrides = new HashMap<>();
        for (AttributedVertex vertex : graph.vertexSet()) {
            String vertexType = vertex.getVertexType();
            String color = "#d1d5db";
            if (VISITED_BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
                VISITED_BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
                color = "#fdba74";
            } else if (BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
                BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
                color = "#fecaca";
            } else if (VISITED_INTERNAL_VERTEX_TYPE.equals(vertexType)) {
                color = reachableVertexColorOverrides.getOrDefault(vertex.getId(), getVertexFillColor(vertex));
            } else if (VISITED_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
                color = reachableVertexColorOverrides.getOrDefault(vertex.getId(), getVertexFillColor(vertex));
            }
            overrides.put(vertex.getId(), color);
        }
        return overrides;
    }

    private Map<String, String> buildDynamicEdgeColorOverrides(AttributedGraph graph) {
        Map<String, String> overrides = new HashMap<>();
        for (AttributedEdge edge : graph.edgeSet()) {
            AttributedVertex sourceVertex = graph.getEdgeSource(edge);
            AttributedVertex targetVertex = graph.getEdgeTarget(edge);
            if (sourceVertex == null || targetVertex == null) {
                continue;
            }

            String edgeKey = buildEdgeKey(sourceVertex, targetVertex);
            if (isVisitedBranchEdge(edge)) {
                overrides.put(edgeKey, "#fdba74");
            } else if (isObservedBranchEdge(edge)) {
                overrides.put(edgeKey, "#dc2626");
            } else if (isVisitedEdge(edge)) {
                overrides.put(edgeKey, reachableEdgeColorOverrides.getOrDefault(edgeKey, "#7dc3f7"));
            }
        }
        return overrides;
    }

    private int compareVerticesForLayerLayout(AttributedVertex left, AttributedVertex right) {
        int leftOrder = getVertexOwnershipOrder(left);
        int rightOrder = getVertexOwnershipOrder(right);
        if (leftOrder != rightOrder) {
            return Integer.compare(leftOrder, rightOrder);
        }
        return VERTEX_ORDER.compare(left, right);
    }

    private int getVertexOwnershipOrder(AttributedVertex vertex) {
        String seedId = layoutVertexOwnerGroup.get(vertex.getId());
        if (seedId == null) {
            return Integer.MAX_VALUE;
        }
        return layoutGroupOrder.getOrDefault(seedId, Integer.MAX_VALUE - 1);
    }

    private String getVertexOwnershipGroupKey(AttributedVertex vertex) {
        String seedId = layoutVertexOwnerGroup.get(vertex.getId());
        if (seedId == null) {
            return "~shared";
        }
        return seedId;
    }

    private int computeLayerHeightUnits(List<AttributedVertex> layerVertices) {
        if (layerVertices.isEmpty()) {
            return 1;
        }
        return layerVertices.size() + countLayerOwnershipBreaks(layerVertices);
    }

    private int computeRenderedLayerHeight(List<AttributedVertex> layerVertices) {
        if (layerVertices.isEmpty()) {
            return BOX_HEIGHT;
        }
        return BOX_HEIGHT +
            ((layerVertices.size() - 1) * ROW_GAP) +
            (countLayerOwnershipBreaks(layerVertices) * GROUP_GAP);
    }

    private int countLayerOwnershipBreaks(List<AttributedVertex> layerVertices) {
        int breaks = 0;
        String previousGroupKey = null;
        for (AttributedVertex vertex : layerVertices) {
            String currentGroupKey = getVertexOwnershipGroupKey(vertex);
            if (previousGroupKey != null && !previousGroupKey.equals(currentGroupKey)) {
                breaks++;
            }
            previousGroupKey = currentGroupKey;
        }
        return breaks;
    }

    private GraphLayout buildOwnershipBandLayout(TreeMap<Integer, List<AttributedVertex>> globalLayerMap) {
        List<String> ownershipOrder = getOwnershipBandOrder(globalLayerMap);
        Map<String, TreeMap<Integer, List<AttributedVertex>>> bandLayers = new HashMap<>();
        for (String ownershipKey : ownershipOrder) {
            bandLayers.put(ownershipKey, new TreeMap<>());
        }

        for (Map.Entry<Integer, List<AttributedVertex>> layerEntry : globalLayerMap.entrySet()) {
            Integer layerIndex = layerEntry.getKey();
            for (AttributedVertex vertex : layerEntry.getValue()) {
                String ownershipKey = getVertexOwnershipGroupKey(vertex);
                TreeMap<Integer, List<AttributedVertex>> ownershipLayerMap =
                    bandLayers.computeIfAbsent(ownershipKey, ignored -> new TreeMap<>());
                ownershipLayerMap.computeIfAbsent(layerIndex, ignored -> new ArrayList<>()).add(vertex);
            }
        }

        int maxLayerIndex = globalLayerMap.isEmpty() ? 0 : globalLayerMap.lastKey();
        int width = (MARGIN_X * 2) + BOX_WIDTH + (Math.max(1, maxLayerIndex + 1) - 1) * LAYER_GAP;
        List<NodeLayout> nodeLayouts = new ArrayList<>();
        Map<String, NodeLayout> positions = new HashMap<>();
        List<BandLabel> bandLabels = new ArrayList<>();
        int currentBandY = HEADER_HEIGHT + MARGIN_Y;

        for (String ownershipKey : ownershipOrder) {
            TreeMap<Integer, List<AttributedVertex>> ownershipLayerMap = bandLayers.get(ownershipKey);
            if (ownershipLayerMap == null || ownershipLayerMap.isEmpty()) {
                continue;
            }

            int bandHeight = computeBandHeight(ownershipLayerMap);
            int layerCount = ownershipLayerMap.size();
            for (Map.Entry<Integer, List<AttributedVertex>> layerEntry : ownershipLayerMap.entrySet()) {
                Integer layerIndex = layerEntry.getKey();
                List<AttributedVertex> layerVertices = new ArrayList<>(layerEntry.getValue());
                layerVertices.sort(this::compareVerticesForLayerLayout);

                int totalLayerHeight = computeRenderedLayerHeight(layerVertices);
                int x = MARGIN_X + (layerIndex * LAYER_GAP);
                int yStart = currentBandY + ((bandHeight - totalLayerHeight) / 2);
                int currentY = yStart;
                String previousGroupKey = null;

                for (AttributedVertex vertex : layerVertices) {
                    String currentGroupKey = getVertexOwnershipGroupKey(vertex);
                    if (previousGroupKey != null && !previousGroupKey.equals(currentGroupKey)) {
                        currentY += GROUP_GAP;
                    }
                    NodeLayout nodeLayout = new NodeLayout(
                        vertex,
                        layerIndex,
                        x,
                        currentY,
                        getVertexFillColor(vertex)
                    );
                    nodeLayouts.add(nodeLayout);
                    positions.put(vertex.getId(), nodeLayout);
                    currentY += ROW_GAP;
                    previousGroupKey = currentGroupKey;
                }
            }

            bandLabels.add(new BandLabel(getDisplayBandName(ownershipKey), currentBandY + 14));
            currentBandY += bandHeight + BAND_GAP;
        }

        nodeLayouts.sort((left, right) -> {
            int yCompare = Integer.compare(left.y, right.y);
            if (yCompare != 0) {
                return yCompare;
            }
            if (left.layer != right.layer) {
                return Integer.compare(left.layer, right.layer);
            }
            return compareVerticesForLayerLayout(left.vertex, right.vertex);
        });

        int height = Math.max(
            HEADER_HEIGHT + (MARGIN_Y * 2) + BOX_HEIGHT,
            currentBandY - BAND_GAP + MARGIN_Y
        );
        return new GraphLayout(width, height, maxLayerIndex + 1, nodeLayouts, positions, bandLabels);
    }

    private int computeBandHeight(TreeMap<Integer, List<AttributedVertex>> ownershipLayerMap) {
        int maxHeight = BOX_HEIGHT;
        for (List<AttributedVertex> layerVertices : ownershipLayerMap.values()) {
            List<AttributedVertex> orderedVertices = new ArrayList<>(layerVertices);
            orderedVertices.sort(this::compareVerticesForLayerLayout);
            maxHeight = Math.max(maxHeight, computeRenderedLayerHeight(orderedVertices));
        }
        return maxHeight;
    }

    private List<String> getOwnershipBandOrder(TreeMap<Integer, List<AttributedVertex>> globalLayerMap) {
        Set<String> ownershipKeys = new TreeSet<>((left, right) -> {
            int leftOrder = getOwnershipSortOrder(left);
            int rightOrder = getOwnershipSortOrder(right);
            if (leftOrder != rightOrder) {
                return Integer.compare(leftOrder, rightOrder);
            }
            return left.compareTo(right);
        });

        for (List<AttributedVertex> layerVertices : globalLayerMap.values()) {
            for (AttributedVertex vertex : layerVertices) {
                ownershipKeys.add(getVertexOwnershipGroupKey(vertex));
            }
        }

        return new ArrayList<>(ownershipKeys);
    }

    private int getOwnershipSortOrder(String ownershipKey) {
        if ("~shared".equals(ownershipKey)) {
            return Integer.MAX_VALUE - 2;
        }
        if ("~unreachable".equals(ownershipKey)) {
            return Integer.MAX_VALUE - 1;
        }
        if ("~cmd".equals(ownershipKey)) {
            return Integer.MAX_VALUE;
        }
        return layoutGroupOrder.getOrDefault(ownershipKey, Integer.MAX_VALUE - 3);
    }

    private String getDisplayBandName(String ownershipKey) {
        if ("~cmd".equals(ownershipKey)) {
            return "excluded";
        }
        if ("~shared".equals(ownershipKey)) {
            return "shared";
        }
        if ("~unreachable".equals(ownershipKey)) {
            return "unreachable";
        }
        return ownershipKey;
    }

    private Path writeDotFile(
        AttributedGraph graph,
        String filename,
        Map<String, String> vertexColorOverrides,
        Map<String, String> edgeColorOverrides
    ) throws IOException {
        Path outPath = getOutputPath(filename);
        Files.createDirectories(outPath.getParent());

        List<AttributedVertex> vertices = new ArrayList<>(graph.vertexSet());
        vertices.sort(VERTEX_ID_ORDER);

        List<AttributedEdge> edges = getSortedEdges(graph);
        boolean includeBaseEdges = filename.contains("static");

        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(outPath))) {
            writer.println("digraph callgraph {");
            writer.println("  rankdir=LR;");
            writer.println("  graph [splines=true, overlap=false];");
            writer.println("  node [style=filled, shape=box, fontname=\"Helvetica\"];");
            writer.println("  edge [fontname=\"Helvetica\"];");

            for (AttributedVertex vertex : vertices) {
                String fillColor = getVertexFillColor(vertex);
                if (vertexColorOverrides != null && vertexColorOverrides.containsKey(vertex.getId())) {
                    fillColor = vertexColorOverrides.get(vertex.getId());
                }
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
                if (!includeBaseEdges && !isHighlightedEdge(edge)) {
                    continue;
                }
                AttributedVertex source = graph.getEdgeSource(edge);
                AttributedVertex target = graph.getEdgeTarget(edge);
                String edgeKey = buildEdgeKey(source, target);
                if (edgeColorOverrides != null && edgeColorOverrides.containsKey(edgeKey)) {
                    writer.printf(
                        "  \"%s\" -> \"%s\" [color=\"%s\", penwidth=\"1.9\"];%n",
                        escapeDot(source.getId()),
                        escapeDot(target.getId()),
                        edgeColorOverrides.get(edgeKey)
                    );
                    continue;
                }
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
                } else if (isReachableEdge(edge)) {
                    writer.printf(
                        "  \"%s\" -> \"%s\" [color=\"#f08080\", penwidth=\"1.8\"];%n",
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

    private Color applyAlpha(Color color, int alpha) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue(), alpha);
    }

    private boolean isExternalVertexType(String vertexType) {
        return (
            EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
            REACHABLE_EXTERNAL_VERTEX_TYPE.equals(vertexType) ||
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

    private boolean isReachableEdge(AttributedEdge edge) {
        return REACHABLE_EDGE_TYPE.equals(edge.getEdgeType());
    }

    private boolean isHighlightedEdge(AttributedEdge edge) {
        return isVisitedEdge(edge) || isObservedBranchEdge(edge) || isReachableEdge(edge);
    }

    private String getVertexFillColor(AttributedVertex vertex) {
        String vertexType = vertex.getVertexType();
        if (VISITED_BRANCH_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            VISITED_BRANCH_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return "#fdba74";
        }
        if (REACHABLE_INTERNAL_VERTEX_TYPE.equals(vertexType) ||
            REACHABLE_EXTERNAL_VERTEX_TYPE.equals(vertexType)) {
            return "#f6a19a";
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
        private final List<BandLabel> bandLabels;

        private GraphLayout(
            int width,
            int height,
            int layerCount,
            List<NodeLayout> nodes,
            Map<String, NodeLayout> positions,
            List<BandLabel> bandLabels
        ) {
            this.width = width;
            this.height = height;
            this.layerCount = layerCount;
            this.nodes = nodes;
            this.positions = positions;
            this.bandLabels = bandLabels;
        }
    }

    private static final class BandLabel {
        private final String text;
        private final int y;

        private BandLabel(String text, int y) {
            this.text = text;
            this.y = y;
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

    private static final class ReachabilitySet {
        private final Set<String> vertexIds = new TreeSet<>();
        private final Set<String> edgeKeys = new TreeSet<>();
    }

    private static final class LayoutGrouping {
        private final Map<String, String> vertexOwnerGroup = new HashMap<>();
        private final Map<String, Integer> groupOrder = new HashMap<>();
    }

}
