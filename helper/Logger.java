package helper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.IntPredicate;
import java.util.function.Supplier;

public class Logger {
    private static Logger activeLogger;

    private final String basePath;
    private final String[] filenames;
    private final IntPredicate printerMask;
    private final Supplier<String> phaseSupplier;
    private final Supplier<String> currentTaskNameSupplier;
    private final Supplier<String> currentDeviceNameSupplier;
    private final BooleanSupplier interruptedSupplier;
    private final BooleanSupplier userModeSupplier;
    private final BooleanSupplier toMainSupplier;
    private final int maxBufferedLines;
    private final Deque<String> logBuffer;

    private PrintWriter[] pw;
    private final Map<String, PrintWriter> taskpw = new HashMap<>();
    private final Map<String, PrintWriter> devicepw = new HashMap<>();

    public Logger(
        String basePath,
        String[] filenames,
        IntPredicate printerMask,
        Supplier<String> phaseSupplier,
        Supplier<String> currentTaskNameSupplier,
        Supplier<String> currentDeviceNameSupplier,
        BooleanSupplier interruptedSupplier,
        BooleanSupplier userModeSupplier,
        BooleanSupplier toMainSupplier,
        int bufferSize
    ) {
        this.basePath = basePath;
        this.filenames = filenames;
        this.printerMask = printerMask;
        this.phaseSupplier = phaseSupplier;
        this.currentTaskNameSupplier = currentTaskNameSupplier;
        this.currentDeviceNameSupplier = currentDeviceNameSupplier;
        this.interruptedSupplier = interruptedSupplier;
        this.userModeSupplier = userModeSupplier;
        this.toMainSupplier = toMainSupplier;
        this.maxBufferedLines = bufferSize;
        this.logBuffer = new ArrayDeque<>(bufferSize);
    }

    public static void setActiveLogger(Logger logger) {
        activeLogger = logger;
    }

    public static void printlnGlobal(String s) {
        requireActiveLogger().println(s);
    }

    public static void printlnGlobal(String s, int i) {
        requireActiveLogger().println(s, i);
    }

    private static Logger requireActiveLogger() {
        if (activeLogger == null) {
            throw new IllegalStateException("Active logger has not been initialized");
        }
        return activeLogger;
    }

    public void initialize() throws IOException {
        recreateLogDirectory();

        pw = new PrintWriter[filenames.length];
        for (int i = 1; i < filenames.length; i++) {
            File outFile = new File(basePath + "/log/" + filenames[i]);
            pw[i] = new PrintWriter(new FileWriter(outFile));
        }
    }

    public void dumpAndFlush() {
        dumpBuffer();
        flush();
    }

    public void flush() {
        if (pw != null) {
            for (PrintWriter p : pw) {
                if (p != null) {
                    p.close();
                }
            }
        }
        for (PrintWriter p : taskpw.values()) {
            if (p != null) {
                p.close();
            }
        }
        for (PrintWriter p : devicepw.values()) {
            if (p != null) {
                p.close();
            }
        }
    }

    public void println(String s) {
        println(s, 0);
    }

    public void println(String s, int i) {
        String s1 = String.format("%s (%s)", s, phaseSupplier.get());
        if (i == 7) {
            printInner(s, i);
        } else if (i != 0) {
            printInner(s1, i);
        }
        printInner(s, 0);
    }

    private void printInner(String s, int i) {
        if (!printerMask.test(i)) {
            return;
        }

        if (i > 0 && pw.length > i) {
            pw[i].println(s);
            if (i == 1) {
                printTask(s);
            } else if (i == 2) {
                printDevice(s);
            }
        } else if (i == -1) {
            pw[pw.length - 1].println(s);
        } else if (i == 0) {
            bufferLine(s);
        }
    }

    private synchronized void bufferLine(String msg) {
        if (logBuffer.size() >= maxBufferedLines) {
            logBuffer.removeFirst();
        }
        logBuffer.addLast(msg);
    }

    private synchronized void dumpBuffer() {
        if (toMainSupplier.getAsBoolean()) {
            File outFile = new File(basePath + "/log/" + filenames[0]);
            try (PrintWriter mainWriter = new PrintWriter(new FileWriter(outFile))) {
                for (String line : logBuffer) {
                    mainWriter.println(line);
                }
            } catch (IOException e) {
                throw new RuntimeException("Failed to write buffered log to " + outFile, e);
            }
            return;
        }

        for (String line : logBuffer) {
            System.out.println(line);
        }
    }

    private void printTask(String s) {
        String taskName = currentTaskNameSupplier.get();
        if (taskName == null || taskName.isEmpty()) {
            pw[1].println("taskName is Empty");
            return;
        }
        if (interruptedSupplier.getAsBoolean()) {
            pw[1].println("skipping task log due to interrupted");
            return;
        }
        if (!userModeSupplier.getAsBoolean()) {
            pw[1].println("skipping task log due to kernel mode");
            return;
        }

        getOrCreateWriter(taskpw, "task", taskName).println(s);
    }

    private void printDevice(String s) {
        String deviceName = currentDeviceNameSupplier.get();
        if (deviceName == null || deviceName.isEmpty()) {
            return;
        }

        getOrCreateWriter(devicepw, "device", deviceName).println(s);
    }

    private PrintWriter getOrCreateWriter(Map<String, PrintWriter> cache, String subdir, String name) {
        PrintWriter writer = cache.get(name);
        if (writer != null) {
            return writer;
        }

        String filename = String.format("%s/log/%s/%s.log", basePath, subdir, name);
        File outFile = new File(filename);
        try {
            outFile.createNewFile();
            writer = new PrintWriter(new FileWriter(outFile));
            cache.put(name, writer);
            return writer;
        } catch (IOException e) {
            throw new RuntimeException("Failed to open log writer for " + filename, e);
        }
    }

    private void recreateLogDirectory() throws IOException {
        Path logDir = Path.of(basePath, "log");
        if (Files.exists(logDir)) {
            try (var paths = Files.walk(logDir)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to delete " + path, e);
                    }
                });
            }
        }
        Files.createDirectories(logDir.resolve("task"));
        Files.createDirectories(logDir.resolve("device"));
    }
}
