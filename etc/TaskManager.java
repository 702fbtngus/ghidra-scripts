package etc;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class TaskManager {
    // private static Task[] taskList = new Task[20];
    // private static int numTasks = 0;
    private static Map<String, Task> taskMap = new LinkedHashMap<>();
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
            .filter(t -> t.state != "")
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
        Task task = new Task(tcb, priority, addr);
        taskMap.put(name, task);
        printAllTasks();
        task.state = "R";
    }

    public static void deleteTask(String name) {
        Task task = taskMap.get(name);
        task.state = "DELETED";
        printAllTasks();
        task.state = "";
    }

    public static void switchTask(String from, String to) {
        Task fromTask = taskMap.get(from);
        Task toTask = taskMap.get(to);
        if (fromTask == null) {
            fromTask = newEmptyTask(to);
        }
        if (toTask == null) {
            toTask = newEmptyTask(to);
        }
        if (fromTask.state == "RUNNING") {
            fromTask.state = "R";
        };
        toTask.state = "RUNNING";
        printAllTasks();
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

    public static void printAllTasks() {
        String line;
        if (currentLine % 35 == 0) {
            Util.println("", 7);
            line = "=";
            for (Entry<String, Task> entry : taskMap.entrySet()) {
            // for (Task task : taskMap.values()) {
                Task task = entry.getValue();
                String name = entry.getKey();
                if (name.length() > 4) {
                    name = name.substring(0, 4);
                }
                String taskTitle = String.format("%s (%s)", name, task.priority);
                line += String.format(" %-8s =", taskTitle);
            }
            line = String.format("%26s    %s", "", line);
            Util.println(line, 7);
        }
        
        line = "";
        char nextSep = '|';
        String realName = null;
        for (Entry<String, Task> entry : taskMap.entrySet()) {
        // for (Task task : taskMap.values()) {
            Task task = entry.getValue();
            if (task.state == "created") {
                String name = entry.getKey();
                if (name.length() > 4) {
                    realName = name;
                    name = realName.substring(0, 4);
                }
                String taskTitle = String.format("%s (%s)", name, task.priority);
                line += String.format("= %-8s ", taskTitle);
                nextSep = '=';
            } else {
                line += nextSep;
                line += String.format(" %-8s ", task.state);
                nextSep = '|';
            }
        }
        line += nextSep;

        line = String.format("[ %-12s | %-7s ]    %s", getCurrentInstr.get(), getCurrentTick.get(), line);
        if (realName != null) {
            line = String.format("%s  (%s)", line, realName);
        }
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
