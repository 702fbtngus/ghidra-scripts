package helper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;

public class TaskManager {
    // private Task[] taskList = new Task[20];
    // private int numTasks = 0;
    private Map<String, Task> taskMap = new LinkedHashMap<>();
    private final int CHUNK_LENGTH = 35;
    private final String GROUP_GAP = "    ";
    public Supplier<Integer> getCurrentTick;
    public Supplier<String> currentPrefixSupplier;
    public int currentLine = 1;

    static class Task {
        public int tcb;
        public int priority;
        public String state;
        public int userStateAddr;

        public Task(int tcb, int priority, int addr) {
            this.tcb = tcb;
            this.priority = priority;
            this.state = "created";
            this.userStateAddr = addr;
        }
    }

    private final Context context;
    private final CPUState cpuState;
    public Logger logger;

    public TaskManager(Context context, CPUState cpuState) {
        this.context = context;
        this.cpuState = cpuState;
    }

    public int[] getAllTCBs() {
        return taskMap.values().stream()
            .filter(t -> t.tcb >= 0 && !t.state.isEmpty())
            .mapToInt(t -> t.tcb)
            .toArray();
    }

    public String getTaskNameByTCB(int tcb) {
        return taskMap.entrySet().stream()
            .filter(entry -> entry.getValue().tcb == tcb)
            .map(Entry::getKey)
            .findFirst()
            .orElse(null);
    }

    public int getPriority(String name) {
        Task task = taskMap.get(name);
        if (task != null) {
            return task.priority;
        }
        return -1;
    }

    public Task newEmptyTask(String name) {
        Task task = new Task(-1, -1, -1);
        taskMap.put(name, task);
        // task.state = "R";
        return task;
    }

    public void createTask(String name, int tcb, int priority, int addr) {
        Task existingTask = taskMap.get(name);
        Task task = new Task(tcb, priority, addr);
        if (existingTask != null && !existingTask.state.isEmpty() && !"created".equals(existingTask.state)) {
            task.state = existingTask.state;
        } else {
            task.state = "R";
        }
        taskMap.put(name, task);
        printTaskEvent("NEW TASK CREATED", name, priority);
        printAllTasks();
    }

    public void deleteTask(String name) {
        Task task = taskMap.get(name);
        int priority = task.priority;
        task.state = "";
        printTaskEvent("TASK DELETED", name, priority);
    }

    public void switchTask(String from, String to) {
        Task fromTask = null;
        if (from != null && !from.isEmpty()) {
            fromTask = taskMap.get(from);
        }
        Task toTask = taskMap.get(to);
        boolean shouldPrint = fromTask != null && toTask != null;
        if (from != null && !from.isEmpty() && fromTask == null) {
            fromTask = newEmptyTask(from);
        }
        if (toTask == null) {
            toTask = newEmptyTask(to);
        }
        if (fromTask != null && "RUNNING".equals(fromTask.state)) {
            fromTask.state = "R";
        }
        toTask.state = "RUNNING";
        if (shouldPrint) {
            printAllTasks();
        }
    }

    public void readyTask(String name, int prio) {
        Task task = taskMap.get(name);
        task.state = String.format("R", prio);;
    }

    public void delayTask(String name, int until) {
        Task task = taskMap.get(name);
        task.state = String.format("D %x", until);;
    }

    public void suspendTask(String name) {
        Task task = taskMap.get(name);
        task.state = String.format("S");;
    }

    public void terminateTask(String name) {
        Task task = taskMap.get(name);
        task.state = String.format("WT");;
    }

    public void changePrio(String name, int prio) {
        Task task = taskMap.get(name);
        // if (task == null) {
        //     return;
        // }
        // fromTask.state = "";
        String state = task.state;
        task.state = String.format("P %s -> %s", task.priority, prio);
        printAllTasks();
        task.priority = prio;
        task.state = state;
    }
    
    public int getUserAddr(String name) {
        Task task = taskMap.get(name);
        if (task != null) {
            return task.userStateAddr;
        }
        return 0;
    }
    
    public void setUserAddr(String name, int sp) {
        Task task = taskMap.get(name);
        if (task != null) {
            task.userStateAddr = sp;
        }
    }
    
    public void monitorTasks(Address addr) {

        int[] numReadyTasks = {
            cpuState.getRAMValue(0x13e8),
            cpuState.getRAMValue(0x13fc),
            cpuState.getRAMValue(0x1410),
            cpuState.getRAMValue(0x1424),
            cpuState.getRAMValue(0x1438),
        };
        for (int i = 0; i < numReadyTasks.length; i++) {
            if (context.currentNumReadyTasks[i] != numReadyTasks[i]) {
                logger.println(String.format(
                    "# ready tasks (priority %d): %d -> %d",
                    i,
                    context.currentNumReadyTasks[i],
                    numReadyTasks[i]
                ), 6);
                context.currentNumReadyTasks[i] = numReadyTasks[i];
            }
        }

        if (addr.getOffset() == 0x8002f900l) {
            // update pxCurrentTCB
            // int currentTCB = getRAMValue(getRegisterValue("R8"));
            int currentTCB = cpuState.getRAMValue(0x1398);
            String newTaskName = cpuState.readString(currentTCB + 0x34);
            if (context.currentTaskName.compareTo(newTaskName) != 0) {
                int currentTick = cpuState.getRAMValue(0x13a0);
                logger.println(String.format("task switched 2: %s (current tickCount: %d)", newTaskName, currentTick), 6);
                switchTask(context.currentTaskName, newTaskName);
                // println("current tickCount: " + currentTick, 6);
                context.currentTaskName = newTaskName;

            }
        }
        if (addr.getOffset() == 0x8002fef2l) {
            // task delete done
            // int currentTCB = getRAMValue(getRegisterValue("R8"));
            int currentTCB = cpuState.getRAMValue(0x1398);
            String taskName = cpuState.readString(currentTCB + 0x34);
            logger.println("task deleted: " + taskName, 6);
            deleteTask(taskName);
        }

        if (addr.getOffset() == 0x80030168l) {
            // xTaskCreate done
            int newTCB = cpuState.getRegisterValue("R4");
            int prio = cpuState.getRAMValue(newTCB + 0x2c);
            String taskName = cpuState.readString(newTCB + 0x34);
            int pxStack = cpuState.getRAMValue(newTCB);
            int pxTopOfStack = cpuState.getRAMValue(newTCB + 0x30);
            logger.println(String.format("new task created at %s: %s (%s)", newTCB, taskName, prio), 6);
            logger.println(String.format("pxStack: 0x%X, pxTopOfStack: 0x%X", pxStack, pxTopOfStack), 6);
            createTask(taskName, newTCB, prio, pxStack + 0x24);
        }
    }

    private List<Entry<String, Task>> getSortedTasks() {
        return taskMap.entrySet().stream()
            .filter(entry -> entry.getValue().priority >= 0)
            .filter(entry -> !entry.getValue().state.isEmpty())
            .sorted((left, right) -> Integer.compare(right.getValue().priority, left.getValue().priority))
            .collect(Collectors.toList());
    }

    private String shortenName(String name) {
        if (name.length() > 4) {
            return name.substring(0, 4);
        }
        return name;
    }

    private String buildHeaderGroup(List<Entry<String, Task>> group) {
        String line = "=";
        for (Entry<String, Task> entry : group) {
            String taskTitle = String.format("%s (%s)", shortenName(entry.getKey()), entry.getValue().priority);
            line += String.format(" %-8s =", taskTitle);
        }
        return line;
    }

    private String buildStateGroup(List<Entry<String, Task>> group) {
        String line = "|";
        for (Entry<String, Task> entry : group) {
            line += String.format(" %-8s |", entry.getValue().state);
        }
        return line;
    }

    private List<List<Entry<String, Task>>> getPriorityGroups(List<Entry<String, Task>> sortedTasks) {
        List<List<Entry<String, Task>>> groups = new java.util.ArrayList<>();
        Integer currentPriority = null;
        List<Entry<String, Task>> currentGroup = null;

        for (Entry<String, Task> entry : sortedTasks) {
            if (currentPriority == null || currentPriority.intValue() != entry.getValue().priority) {
                currentPriority = entry.getValue().priority;
                currentGroup = new java.util.ArrayList<>();
                groups.add(currentGroup);
            }
            currentGroup.add(entry);
        }
        return groups;
    }

    private void printHeaderLine() {
        List<Entry<String, Task>> sortedTasks = getSortedTasks();
        if (sortedTasks.isEmpty()) {
            return;
        }
        List<List<Entry<String, Task>>> groups = getPriorityGroups(sortedTasks);
        String line = groups.stream()
            .map(this::buildHeaderGroup)
            .collect(Collectors.joining(GROUP_GAP));
        int prefixWidth = currentPrefixSupplier.get().length();
        Logger.printlnGlobal("", 7);
        Logger.printlnGlobal(String.format("%" + prefixWidth + "s    %s", "", line), 7);
        currentLine = 0;
    }

    private void printTaskEvent(String event, String name, int priority) {
        Logger.printlnGlobal("", 7);
        Logger.printlnGlobal(String.format("=== %s : %s (%s) ===", event, name, priority), 7);
        currentLine = 0;
        // printHeaderLine();
    }

    private void printAllTasks() {
        List<Entry<String, Task>> sortedTasks = getSortedTasks();
        if (sortedTasks.isEmpty()) {
            return;
        }
        if (currentLine % CHUNK_LENGTH == 0) {
            printHeaderLine();
        }

        List<List<Entry<String, Task>>> groups = getPriorityGroups(sortedTasks);
        String line = groups.stream()
            .map(this::buildStateGroup)
            .collect(Collectors.joining(GROUP_GAP));
        line = String.format("%s    %s", currentPrefixSupplier.get(), line);
        //     Task task = taskList[i];
        //     if (task.state == "created"
        //         || (i > 0 && taskList[i-1].state == "created")
        //     ) {
        //         String taskTitle = String.format("%s (%s)", task.name, task.priority);
        //         // line += "= ";
        //         line += String.format("= %-12s ", taskTitle);
        //     } else {
        //         line += String.format("| %-12s ", task.state);
        //     }
        // }
        // if (taskList[numTasks - 1].state == "created") {
        //     line += "=";
        // } else {
        //     line += "|";
        // }
        Logger.printlnGlobal(line, 7);
        currentLine++;
    }

}
