package helper;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public final class DynamicFlowTracker implements AutoCloseable {
    private static final String EMUL_SUFFIX = ".emul";

    private final Context context;
    private final Logger logger;
    private final ReferenceManager referenceManager;
    private final boolean enabled;

    private int transactionId = -1;
    private int recordedCount = 0;
    private int skippedDuplicateCount = 0;
    private int skippedMissingFunctionCount = 0;

    public DynamicFlowTracker(Context context, Logger logger) {
        this.context = context;
        this.logger = logger;
        this.referenceManager = context.currentProgram.getReferenceManager();
        this.enabled = isEmulatedProgram(context.currentProgram.getDomainFile());

        if (enabled) {
            transactionId = context.currentProgram.startTransaction("record emulated dynamic flows");
            logger.println("Dynamic flow tracking enabled for " + getProgramName(), 6);
        } else {
            logger.println("Dynamic flow tracking disabled for " + getProgramName(), 6);
        }
    }

    public void recordComputedFlow(Instruction instruction, Address nextAddress) {
        if (!enabled || instruction == null || nextAddress == null) {
            return;
        }

        FlowType flowType = instruction.getFlowType();
        if (flowType == null || !flowType.isComputed() || (!flowType.isCall() && !flowType.isJump())) {
            return;
        }

        Address fallthrough = instruction.getFallThrough();
        if (fallthrough != null && fallthrough.equals(nextAddress) && flowType.hasFallthrough()) {
            return;
        }

        Function sourceFunction =
            context.currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
        Function targetFunction =
            context.currentProgram.getFunctionManager().getFunctionContaining(nextAddress);

        if (sourceFunction == null || targetFunction == null) {
            skippedMissingFunctionCount++;
            return;
        }

        if (sourceFunction.equals(targetFunction)) {
            return;
        }

        RefType referenceType = getReferenceType(flowType);
        if (referenceType == null) {
            return;
        }

        if (hasFlowReference(instruction.getAddress(), nextAddress, referenceType)) {
            skippedDuplicateCount++;
            return;
        }

        referenceManager.addMemoryReference(
            instruction.getAddress(),
            nextAddress,
            referenceType,
            SourceType.USER_DEFINED,
            ReferenceManager.MNEMONIC
        );
        recordedCount++;

        logger.println(String.format(
            "Recorded dynamic %s flow: %s (%s) -> %s (%s)",
            flowType.isCall() ? "call" : "jump",
            instruction.getAddress(),
            sourceFunction.getName(),
            nextAddress,
            targetFunction.getName()
        ), 6);
    }

    private boolean hasFlowReference(Address fromAddress, Address toAddress, RefType referenceType) {
        for (Reference reference : referenceManager.getFlowReferencesFrom(fromAddress)) {
            if (!toAddress.equals(reference.getToAddress())) {
                continue;
            }
            if (referenceType.equals(reference.getReferenceType())) {
                return true;
            }
        }
        return false;
    }

    private RefType getReferenceType(FlowType flowType) {
        if (flowType.isCall()) {
            return flowType.isConditional()
                ? RefType.CONDITIONAL_COMPUTED_CALL
                : RefType.COMPUTED_CALL;
        }
        if (flowType.isJump()) {
            return flowType.isConditional()
                ? RefType.CONDITIONAL_COMPUTED_JUMP
                : RefType.COMPUTED_JUMP;
        }
        return null;
    }

    private boolean isEmulatedProgram(DomainFile domainFile) {
        return domainFile != null && domainFile.getName().endsWith(EMUL_SUFFIX);
    }

    private String getProgramName() {
        DomainFile domainFile = context.currentProgram.getDomainFile();
        if (domainFile != null) {
            return domainFile.getName();
        }
        return context.currentProgram.getName();
    }

    @Override
    public void close() {
        if (!enabled || transactionId < 0) {
            return;
        }

        context.currentProgram.endTransaction(transactionId, true);
        logger.println(String.format(
            "Committed dynamic flow metadata: recorded=%d duplicate=%d missing-function=%d",
            recordedCount,
            skippedDuplicateCount,
            skippedMissingFunctionCount
        ), 6);
        transactionId = -1;
    }
}
