package etc;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class TaskManager {
    // private static Task[] taskList = new Task[20];
    // private static int numTasks = 0;
    private static Map<String, Task> taskMap = new LinkedHashMap<>();
    private static final int CHUNK_LENGTH = 35;
    private static final String GROUP_GAP = "    ";
    public static Supplier<Integer> getCurrentTick;
    public static Supplier<String> getCurrentInstr;
    public static int currentLine = 1;

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

    private TaskManager() {
        // TaskManager is a utility class
        throw new AssertionError("No instances");
    }

    public static int[] getAllTCBs() {
        return taskMap.values().stream()
            .filter(t -> t.tcb >= 0 && !t.state.isEmpty())
            .mapToInt(t -> t.tcb)
            .toArray();
    }

    public static Task newEmptyTask(String name) {
        Task task = new Task(-1, -1, -1);
        taskMap.put(name, task);
        // printAllTasks();
        // task.state = "R";
        return task;
    }

    public static void createTask(String name, int tcb, int priority, int addr) {
        Task existingTask = taskMap.get(name);
        Task task = new Task(tcb, priority, addr);
        if (existingTask != null && !existingTask.state.isEmpty() && !"created".equals(existingTask.state)) {
            task.state = existingTask.state;
        } else {
            task.state = "R";
        }
        taskMap.put(name, task);
        printTaskEvent("NEW TASK CREATED", name, priority);
        printAllTasks(false);
    }

    public static void deleteTask(String name) {
        Task task = taskMap.get(name);
        int priority = task.priority;
        task.state = "";
        printTaskEvent("TASK DELETED", name, priority);
        printAllTasks(false);
    }

    public static void switchTask(String from, String to) {
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

    public static void readyTask(String name, int prio) {
        Task task = taskMap.get(name);
        task.state = String.format("R", prio);;
        // printAllTasks();
    }

    public static void delayTask(String name, int until) {
        Task task = taskMap.get(name);
        task.state = String.format("D %s", until);;
        // printAllTasks();
    }

    public static void suspendTask(String name) {
        Task task = taskMap.get(name);
        task.state = String.format("S");;
        // printAllTasks();
    }

    public static void terminateTask(String name) {
        Task task = taskMap.get(name);
        task.state = String.format("WT");;
        // printAllTasks();
    }

    public static void changePrio(String name, int prio) {
        Task task = taskMap.get(name);
        // fromTask.state = "";
        String state = task.state;
        task.state = String.format("P %s -> %s", task.priority, prio);
        printAllTasks();
        task.priority = prio;
        task.state = state;
    }
    
    public static int getUserAddr(String name) {
        Task task = taskMap.get(name);
        if (task != null) {
            return task.userStateAddr;
        }
        return 0;
    }
    
    public static void setUserAddr(String name, int sp) {
        Task task = taskMap.get(name);
        if (task != null) {
            task.userStateAddr = sp;
        }
    }

    private static List<Entry<String, Task>> getSortedTasks() {
        return taskMap.entrySet().stream()
            .filter(entry -> entry.getValue().priority >= 0)
            .sorted((left, right) -> Integer.compare(right.getValue().priority, left.getValue().priority))
            .collect(Collectors.toList());
    }

    private static String shortenName(String name) {
        if (name.length() > 4) {
            return name.substring(0, 4);
        }
        return name;
    }

    private static String buildHeaderGroup(List<Entry<String, Task>> group) {
        String line = "=";
        for (Entry<String, Task> entry : group) {
            String taskTitle = String.format("%s (%s)", shortenName(entry.getKey()), entry.getValue().priority);
            line += String.format(" %-8s =", taskTitle);
        }
        return line;
    }

    private static String buildStateGroup(List<Entry<String, Task>> group) {
        String line = "|";
        for (Entry<String, Task> entry : group) {
            line += String.format(" %-8s |", entry.getValue().state);
        }
        return line;
    }

    private static List<List<Entry<String, Task>>> getPriorityGroups(List<Entry<String, Task>> sortedTasks) {
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

    private static void printHeaderLine() {
        List<Entry<String, Task>> sortedTasks = getSortedTasks();
        if (sortedTasks.isEmpty()) {
            return;
        }
        List<List<Entry<String, Task>>> groups = getPriorityGroups(sortedTasks);
        String line = groups.stream()
            .map(TaskManager::buildHeaderGroup)
            .collect(Collectors.joining(GROUP_GAP));
        Util.println("", 7);
        Util.println(String.format("%26s    %s", "", line), 7);
    }

    private static void printTaskEvent(String event, String name, int priority) {
        Util.println("", 7);
        Util.println(String.format("=== %s : %s (%s) ===", event, name, priority), 7);
        printHeaderLine();
    }

    public static void printAllTasks() {
        printAllTasks(currentLine % CHUNK_LENGTH == 0);
    }

    private static void printAllTasks(boolean printHeader) {
        List<Entry<String, Task>> sortedTasks = getSortedTasks();
        if (sortedTasks.isEmpty()) {
            return;
        }
        if (printHeader) {
            printHeaderLine();
        }

        List<List<Entry<String, Task>>> groups = getPriorityGroups(sortedTasks);
        String line = groups.stream()
            .map(TaskManager::buildStateGroup)
            .collect(Collectors.joining(GROUP_GAP));
        line = String.format("[ %-12s | %-7s ]    %s", getCurrentInstr.get(), getCurrentTick.get(), line);
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
        Util.println(line, 7);
        currentLine++;
    }

}
