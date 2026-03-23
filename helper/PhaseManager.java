package helper;

import java.util.HashMap;
import java.util.Map;

public final class PhaseManager {
    private static final String BOOT_TASK_NAME = "";
    private static final String BOOT_DISPLAY_NAME = "boot";
    private static final int TASK_WIDTH = 4;
    private static final int FUNCTION_WIDTH = 10;
    private static final int PHASE_WIDTH = 3;
    private static final String DEFAULT_PHASE_CODE = "-00";

    private static final PhaseBoundary[] NO_PHASE_BOUNDARIES = new PhaseBoundary[0];

    private static final PhaseBoundary[] INIT_PHASE_BOUNDARIES = {
        boundary(0x8001db06L, phase(1)),  // gs_mpu3300_init
        boundary(0x8001db0aL, phase(2)),  // gs_mpu3300_register_commands
        boundary(0x8001db0eL, phase(3)),  // gs_hmc5843_init
        boundary(0x8001db12L, phase(4)),  // gs_hmc5843_register_commands
        boundary(0x8001db16L, phase(5)),  // gs_fm33256b_register_commands
        boundary(0x8001db1aL, phase(6)),  // gs_a3200_adc_register_commands
        boundary(0x8001db1eL, phase(7)),  // gs_a3200_pwm_register_commands
        boundary(0x8001db22L, phase(8)),  // gs_embed_register_commands
        boundary(0x8001db26L, phase(9)),  // gs_vmem_register_commands
        boundary(0x8001db2aL, phase(10)), // gs_checkout_register_commands
        boundary(0x8001db2eL, phase(11)), // sys_register_commands
        boundary(0x8001db32L, phase(12)), // gnss_register_commands
        boundary(0x8001db36L, phase(13)), // ants_register_commands
        boundary(0x8001db3aL, phase(14)), // eps_register_commands
        boundary(0x8001db3eL, phase(15)), // bat_register_commands
        boundary(0x8001db42L, phase(16)), // vrx_register_commands
        boundary(0x8001db46L, phase(17)), // utx_register_commands
        boundary(0x8001db4aL, phase(18)), // adcs_tm_register_commands
        boundary(0x8001db4eL, phase(19)), // adcs_tc_register_commands
        boundary(0x8001db52L, phase(20)), // hstx_register_commands
        boundary(0x8001db56L, phase(21)), // randev_sys_thread_init
        boundary(0x8001db5aL, phase(22)), // randev_sys_thread_mode_manager
        boundary(0x8001db5eL, phase(23)), // randev_sys_thread_downlink_manager
        boundary(0x8001db62L, phase(24)), // randev_sys_thread_uplink_manager
        boundary(0x8001db66L, phase(25)), // randev_sys_thread_data_manager
        boundary(0x8001dc64L, phase(26)), // gs_console_start
        boundary(0x8001dc68L, phase(27)), // configure_csp
        boundary(0x8001dc6cL, phase(28)), // configure_csp returns; next block starts
    };

    private static final PhaseBoundary[] IDLE_PHASE_BOUNDARIES = {
        boundary(0x8002fe1eL, phase(1)), // vPortEnterCritical: deleted-task cleanup begins
        boundary(0x8002fe50L, phase(2)), // cleanup done; ready-list check / optional SCALL
        boundary(0x8002fe5aL, phase(3)), // vApplicationIdleHook
    };

    private static final PhaseBoundary[] LED_PHASE_BOUNDARIES = {
        boundary(0x8001da3eL, phase(1)), // wdt_clear
        boundary(0x8001da44L, phase(2)), // gs_a3200_led_off
        boundary(0x8001da4aL, phase(3)), // gs_a3200_led_on
        boundary(0x8001da52L, phase(4)), // gs_time_sleep_ms
        boundary(0x8001da58L, phase(5)), // gs_a3200_led_on
        boundary(0x8001da5eL, phase(6)), // gs_a3200_led_off
        boundary(0x8001da66L, phase(7)), // gs_time_sleep_ms
    };

    private static final PhaseBoundary[] SYS_INIT_PHASE_BOUNDARIES = {
        boundary(0x8001b8beL, phase(1)), // wdt_clear
        boundary(0x8001b8c6L, phase(2)), // gs_thread_sleep_ms
        boundary(0x8001b8d4L, phase(3)), // spn_fl512s_read_data
        boundary(0x8001b8e6L, phase(4)), // memset
        boundary(0x8001b8f4L, phase(5)), // randev_sys_overwrite
        boundary(0x8001b8faL, phase(6)), // clyde_eps_set_watchdog
        boundary(0x8001b900L, phase(7)), // utx_set_bitrate
        boundary(0x8001b906L, phase(7)), // gs_thread_exit
    };

    private static final PhaseBoundary[] MODE_PHASE_BOUNDARIES = {
        boundary(0x8001b8a6L, phase(1)), // randev_sys_mode_manager
        boundary(0x80017584L, phase(2)), // mode switch case
        boundary(0x80018272L, phase(3)), // mode done
    };

    private static final PhaseBoundary[] DOWNLINK_PHASE_BOUNDARIES = {
        boundary(0x80017242L, phase(1)),      // spn_fl512s_read_data: load global request block
        boundary(0x80017250L, phase(2)),      // spn_fl512s_read_data: load WOD state block
        boundary(0x80017254L, phase(3)),      // dispatch on glob_var[8]

        boundary(0x80017290L, branch('A', 1)), // '<' branch: parse WOD range / clamp count
        boundary(0x800172e6L, branch('A', 2)), // '<' branch: WOD chunk transmit loop
        boundary(0x8001734eL, branch('A', 3)), // '<' branch: persist WOD cursor
        boundary(0x80017362L, branch('A', 4)), // '<' branch: clear global request flag

        boundary(0x80017368L, branch('B', 1)), // '=' branch: long delay before falling through to '?' path

        boundary(0x80017370L, branch('C', 1)), // '?' branch: init 0x01 header burst
        boundary(0x80017382L, branch('C', 2)), // '?' branch: send header burst
        boundary(0x800173a4L, branch('C', 3)), // '?' branch: image chunk transmit loop

        boundary(0x800173f6L, branch('D', 1)), // '@' branch: init 0x02 header burst
        boundary(0x80017408L, branch('D', 2)), // '@' branch: send header burst
        boundary(0x8001742eL, branch('D', 3)), // '@' branch: image chunk transmit loop

        boundary(0x80017480L, branch('E', 1)), // 'A' branch: init 0x03 header burst
        boundary(0x80017492L, branch('E', 2)), // 'A' branch: send header burst
        boundary(0x800174b8L, branch('E', 3)), // 'A' branch: image chunk transmit loop

        boundary(0x8001750aL, branch('Z', 1)), // default branch: prepare HKD packet buffer
        boundary(0x8001751cL, branch('Z', 2)), // default branch: randev_sys_get_hkd
        boundary(0x80017528L, branch('Z', 3)), // default branch: utx_send_frame
    };

    private static final PhaseBoundary[] UPLINK_PHASE_BOUNDARIES = {
        boundary(0x80017168L, phase(1)),      // spn_fl512s_read_data: load global uplink context
        boundary(0x80017174L, phase(2)),      // vrx_get_frames: poll pending frame count
        boundary(0x80017198L, phase(3)), // vrx_get_frame: per-frame fetch/decode loop
        boundary(0x800171caL, phase(4)), // randev_sys_execute_cmd: branch A command handling
        boundary(0x800171d6L, phase(5)), // utx_send_frame: branch A transmit
        boundary(0x800171e6L, phase(6)), // gs_time_sleep_ms: branch A pacing
        boundary(0x800171eaL, phase(7)), // vrx_remove_frame: branch A cleanup
        boundary(0x800171f4L, phase(8)), // gs_time_sleep_ms: branch A inter-frame pacing
    };

    private static final PhaseBoundary[] DATA_PHASE_BOUNDARIES = NO_PHASE_BOUNDARIES;
    private static final PhaseBoundary[] CONSOLE_PHASE_BOUNDARIES = NO_PHASE_BOUNDARIES;
    private static final PhaseBoundary[] RTE_PHASE_BOUNDARIES = NO_PHASE_BOUNDARIES;

    private final Map<String, TaskPhaseConfig> taskConfigs = buildTaskConfigs();
    private final Map<String, Phase> taskStates = new HashMap<>();
    private final Phase interruptState = new Phase();
    private int totalInstructionCount;

    public void startPhase(String taskName, long counterOffset, String functionName) {
        taskStates.clear();
        interruptState.reset();
        totalInstructionCount = 0;
        updateTaskPhase(taskName, counterOffset, functionName);
    }

    public void updateTaskPhase(String taskName, long counterOffset, String functionName) {
        Phase phase = getTaskPhase(taskName);
        TaskPhaseConfig config = getTaskConfig(taskName);

        if (config.isCycleBoundary(counterOffset)) {
            phase.setCycleNumber(phase.getCycleNumber() + 1);
            phase.setPhaseCode(DEFAULT_PHASE_CODE);
            phase.setPhaseInstructionCount(0);
        }

        String explicitPhaseCode = config.findPhaseCode(counterOffset);
        if (explicitPhaseCode != null && !explicitPhaseCode.equals(phase.getPhaseCode())) {
            phase.setPhaseCode(explicitPhaseCode);
            phase.setPhaseInstructionCount(0);
        }

        phase.setCounterOffset(counterOffset);
        phase.setFunctionName(normalizeFunctionName(functionName));
    }

    public void updateInterruptPhase(long counterOffset, String functionName) {
        interruptState.setCounterOffset(counterOffset);
        interruptState.setFunctionName(normalizeFunctionName(functionName));
    }

    public void beginInterrupt(long counterOffset, String functionName) {
        interruptState.setCounterOffset(counterOffset);
        interruptState.setFunctionName(normalizeFunctionName(functionName));
        interruptState.setPhaseInstructionCount(0);
    }

    public void endInterrupt() {
        interruptState.setCycleNumber(interruptState.getCycleNumber() + 1);
    }

    public void incrementInstructionCount(String taskName, boolean interrupted) {
        if (interrupted) {
            interruptState.setPhaseInstructionCount(interruptState.getPhaseInstructionCount() + 1);
            return;
        }

        Phase phase = getTaskPhase(taskName);
        phase.setPhaseInstructionCount(phase.getPhaseInstructionCount() + 1);
        totalInstructionCount++;
    }

    public void decrementInstructionCount(String taskName) {
        Phase phase = getTaskPhase(taskName);
        phase.setPhaseInstructionCount(phase.getPhaseInstructionCount() - 1);
        totalInstructionCount--;
    }

    public Phase getTaskPhase(String taskName) {
        return taskStates.computeIfAbsent(canonicalTaskName(taskName), key -> {
            Phase phase = new Phase();
            phase.setFunctionName("null");
            return phase;
        });
    }

    public Phase getInterruptPhase() {
        return interruptState;
    }

    public int getTotalInstructionCount() {
        return totalInstructionCount;
    }

    public String formatLogPrefix(String taskName, boolean interrupted) {
        Phase phase = interrupted ? interruptState : getTaskPhase(taskName);
        String functionName = abbreviateFunctionName(phase.getFunctionName());
        long counterOffset = phase.getCounterOffset();

        if (interrupted) {
            return String.format(
                "[ %-4s C:%05d -- I:%06d 0x%08x %-" + FUNCTION_WIDTH + "s ]",
                "intr",
                phase.getCycleNumber(),
                phase.getPhaseInstructionCount(),
                counterOffset,
                functionName
            );
        }
        else if (getTaskConfig(taskName).getCycleBoundary() == null) {
            return String.format(
                "[ %-4s ---- P:%-3s I:%06d 0x%08x %-" + FUNCTION_WIDTH + "s ]",
                getTaskLabel(taskName),
                phase.getPhaseCode(),
                phase.getPhaseInstructionCount(),
                counterOffset,
                functionName
            );
        }

        return String.format(
            "[ %-4s C:%02d P:%-3s I:%06d 0x%08x %-" + FUNCTION_WIDTH + "s ]",
            getTaskLabel(taskName),
            phase.getCycleNumber(),
            phase.getPhaseCode(),
            phase.getPhaseInstructionCount(),
            counterOffset,
            functionName
        );
    }

    public String formatTaskTablePrefix(String taskName, int tick) {
        Phase phase = getTaskPhase(taskName);
        return String.format(
            "[ %-4s C:%02d P:%-3s I:%06d | %-7x ]",
            getTaskLabel(taskName),
            phase.getCycleNumber(),
            phase.getPhaseCode(),
            phase.getPhaseInstructionCount(),
            tick
        );
    }

    private Map<String, TaskPhaseConfig> buildTaskConfigs() {
        Map<String, TaskPhaseConfig> configs = new HashMap<>();
        configs.put("INIT", new TaskPhaseConfig(null, INIT_PHASE_BOUNDARIES, "INIT"));
        configs.put("IDLE", new TaskPhaseConfig(null, IDLE_PHASE_BOUNDARIES, "IDLE"));
        configs.put("LED", new TaskPhaseConfig(0x8001da3eL, LED_PHASE_BOUNDARIES, "LED"));
        configs.put("randev_sys_init", new TaskPhaseConfig(null, SYS_INIT_PHASE_BOUNDARIES, "rand"));
        configs.put("mode_manager", new TaskPhaseConfig(0x8001b89aL, MODE_PHASE_BOUNDARIES, "mode"));
        configs.put("downlink_manage", new TaskPhaseConfig(0x8001b87aL, DOWNLINK_PHASE_BOUNDARIES, "down"));
        configs.put("uplink_manager", new TaskPhaseConfig(0x8001b85aL, UPLINK_PHASE_BOUNDARIES, "upli"));
        configs.put("data_manager", new TaskPhaseConfig(null, DATA_PHASE_BOUNDARIES, "data"));
        configs.put("CONSOLE", new TaskPhaseConfig(null, CONSOLE_PHASE_BOUNDARIES, "CONS"));
        configs.put("RTE", new TaskPhaseConfig(null, RTE_PHASE_BOUNDARIES, "RTE"));
        return configs;
    }

    private TaskPhaseConfig getTaskConfig(String taskName) {
        String canonicalTaskName = canonicalTaskName(taskName);
        TaskPhaseConfig config = taskConfigs.get(canonicalTaskName);
        if (config != null) {
            return config;
        }
        return new TaskPhaseConfig(null, NO_PHASE_BOUNDARIES, null);
    }

    private static PhaseBoundary boundary(long counterOffset, String phaseCode) {
        return new PhaseBoundary(counterOffset, phaseCode);
    }

    private static String phase(int phaseIndex) {
        return String.format("-%02d", phaseIndex);
    }

    private static String branch(char branchId, int phaseIndex) {
        return String.format("%c%02d", branchId, phaseIndex);
    }

    private String getTaskLabel(String taskName) {
        String canonicalTaskName = canonicalTaskName(taskName);
        TaskPhaseConfig config = getTaskConfig(canonicalTaskName);
        String displayName = config.getDisplayName();
        if (displayName == null || displayName.isEmpty()) {
            displayName = canonicalTaskName;
        }
        if (displayName.isEmpty()) {
            displayName = BOOT_DISPLAY_NAME;
        }

        if (displayName.length() > TASK_WIDTH) {
            displayName = displayName.substring(0, TASK_WIDTH);
        }

        return String.format("%-" + TASK_WIDTH + "s", displayName);
    }

    private String canonicalTaskName(String taskName) {
        if (taskName == null || taskName.isEmpty()) {
            return BOOT_TASK_NAME;
        }
        return taskName;
    }

    private String normalizeFunctionName(String functionName) {
        if (functionName == null || functionName.isEmpty()) {
            return "null";
        }
        return functionName;
    }

    private String abbreviateFunctionName(String functionName) {
        String normalized = normalizeFunctionName(functionName);
        if (normalized.length() <= FUNCTION_WIDTH) {
            return String.format("%-" + FUNCTION_WIDTH + "s", normalized);
        }

        int prefixLength = Math.min(4, FUNCTION_WIDTH - 2);
        int suffixLength = Math.min(4, FUNCTION_WIDTH - 2 - prefixLength);
        if (suffixLength <= 0) {
            return normalized.substring(0, FUNCTION_WIDTH);
        }

        String shortened = normalized.substring(0, prefixLength)
            + ".."
            + normalized.substring(normalized.length() - suffixLength);
        return String.format("%-" + FUNCTION_WIDTH + "s", shortened);
    }

    private static String normalizePhaseCode(String phaseCode) {
        if (phaseCode == null || phaseCode.isEmpty()) {
            return DEFAULT_PHASE_CODE;
        }
        if (phaseCode.length() != PHASE_WIDTH) {
            throw new IllegalArgumentException("Phase code must be exactly " + PHASE_WIDTH + " chars: " + phaseCode);
        }
        return phaseCode;
    }

    public static final class TaskPhaseConfig {
        private final Long cycleBoundary;
        private final PhaseBoundary[] phaseBoundaries;
        private final String displayName;

        public TaskPhaseConfig(Long cycleBoundary, PhaseBoundary[] phaseBoundaries, String displayName) {
            this.cycleBoundary = cycleBoundary;
            this.phaseBoundaries = phaseBoundaries.clone();
            this.displayName = displayName;
        }

        public Long getCycleBoundary() {
            return cycleBoundary;
        }

        public PhaseBoundary[] getPhaseBoundaries() {
            return phaseBoundaries.clone();
        }

        public String getDisplayName() {
            return displayName;
        }

        public boolean isCycleBoundary(long counterOffset) {
            return cycleBoundary != null && cycleBoundary.longValue() == counterOffset;
        }

        public String findPhaseCode(long counterOffset) {
            for (PhaseBoundary boundary : phaseBoundaries) {
                if (boundary.getCounterOffset() == counterOffset) {
                    return boundary.getPhaseCode();
                }
            }
            return null;
        }
    }

    public static final class PhaseBoundary {
        private final long counterOffset;
        private final String phaseCode;

        public PhaseBoundary(long counterOffset, String phaseCode) {
            this.counterOffset = counterOffset;
            this.phaseCode = normalizePhaseCode(phaseCode);
        }

        public long getCounterOffset() {
            return counterOffset;
        }

        public String getPhaseCode() {
            return phaseCode;
        }
    }

    public static final class Phase {
        private int cycleNumber;
        private String phaseCode = DEFAULT_PHASE_CODE;
        private int phaseInstructionCount;
        private long counterOffset;
        private String functionName;

        public int getCycleNumber() {
            return cycleNumber;
        }

        public String getPhaseCode() {
            return phaseCode;
        }

        public int getPhaseInstructionCount() {
            return phaseInstructionCount;
        }

        public long getCounterOffset() {
            return counterOffset;
        }

        public String getFunctionName() {
            return functionName;
        }

        public void setCycleNumber(int cycleNumber) {
            this.cycleNumber = cycleNumber;
        }

        public void setPhaseCode(String phaseCode) {
            this.phaseCode = normalizePhaseCode(phaseCode);
        }

        public void setPhaseInstructionCount(int phaseInstructionCount) {
            this.phaseInstructionCount = phaseInstructionCount;
        }

        public void setCounterOffset(long counterOffset) {
            this.counterOffset = counterOffset;
        }

        public void setFunctionName(String functionName) {
            this.functionName = functionName;
        }

        private void reset() {
            cycleNumber = 0;
            phaseCode = DEFAULT_PHASE_CODE;
            phaseInstructionCount = 0;
            counterOffset = 0;
            functionName = "null";
        }
    }
}
