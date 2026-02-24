package etc;

import java.util.ArrayDeque;
import java.util.Deque;

public class LogBuffer {
    private final int maxLines;
    private final Deque<String> buffer;

    public LogBuffer(int maxLines) {
        this.maxLines = maxLines;
        this.buffer = new ArrayDeque<>(maxLines);
    }

    public synchronized void println(String msg) {
        if (buffer.size() >= maxLines) {
            buffer.removeFirst(); // 가장 오래된 로그 제거
        }
        buffer.addLast(msg);
    }

    public synchronized void dump() {
        for (String line : buffer) {
            System.out.println(line);
        }
    }
}
