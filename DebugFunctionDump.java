// Temporary diagnostic dump for selected functions.
// @category CubeSat

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;

public class DebugFunctionDump extends GhidraScript {
    private static final String[] FUNCTIONS = {
        "csp_can_socketcan_init",
        "csp_can_tx",
        "csp_send_direct",
        "csp_iflist_add",
        "csp_route_work",
        "csp_send"
    };

    @Override
    protected void run() throws Exception {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            println("decompiler unavailable: " + decompiler.getLastMessage());
            return;
        }
        try {
            for (String name : FUNCTIONS) {
                Function function = findFunction(functionManager, name);
                if (function == null) {
                    println("missing " + name);
                    continue;
                }
                dumpFunction(decompiler, function);
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private Function findFunction(FunctionManager functionManager, String name) {
        for (Function function : functionManager.getFunctions(true)) {
            if (name.equals(function.getName())) {
                return function;
            }
        }
        return null;
    }

    private void dumpFunction(DecompInterface decompiler, Function function) {
        println("==== " + function.getName() + " @ " + function.getEntryPoint() + " ====");
        DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
        if (results == null || !results.decompileCompleted()) {
            println("decompile failed");
            return;
        }
        if (results.getDecompiledFunction() != null) {
            println(results.getDecompiledFunction().getC());
        }
        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null || highFunction.getPcodeOps() == null) {
            return;
        }
        Iterator<PcodeOpAST> iterator = highFunction.getPcodeOps();
        while (iterator.hasNext()) {
            PcodeOpAST op = iterator.next();
            if (op.getOpcode() == PcodeOp.STORE ||
                op.getOpcode() == PcodeOp.LOAD ||
                op.getOpcode() == PcodeOp.CALLIND) {
                Address address = op.getSeqnum().getTarget();
                println(address + " " + op);
            }
        }
    }
}
