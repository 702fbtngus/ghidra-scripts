package helper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;

import hw.Device;
import hw.UTX;
import hw.VRX;

public class RFModuleSimulator {

    private static final int SERVER_PORT = 10001;
    private static final int BUFFER_SIZE = 0x400;
    private static final int ACCEPT_TIMEOUT_MS = 200;
    private static final int READ_TIMEOUT_MS = 50;
    private static final int IDLE_SLEEP_MS = 10;

    private final Thread simThread;
    private final DeviceManager deviceManager;
    private volatile boolean running = true;
    private boolean waitingForClientLogged = false;

    private ServerSocket serverSocket;
    private Socket clientSocket;

    public RFModuleSimulator(DeviceManager deviceManager) {
        this.deviceManager = deviceManager;
        simThread = new Thread(this::runLoop, "rf.module.simulator");
        simThread.setDaemon(true);
        simThread.start();
    }

    public void stop() {
        running = false;
        closeClient();
        closeServer();
    }

    private void runLoop() {
        try {
            initServer();
            while (running) {
                if (clientSocket == null || clientSocket.isClosed()) {
                    acceptClient();
                    continue;
                }

                int size = recvMessage();
                sendMessage();
                if (size == 0) {
                    sleepQuietly(IDLE_SLEEP_MS);
                }
            }
        } finally {
            closeClient();
            closeServer();
        }
    }

    private void initServer() {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress("0.0.0.0", SERVER_PORT));
            serverSocket.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Logger.printlnGlobal(String.format("[rf_module_simulator_thread] Server bound to port %d @ 0.0.0.0", SERVER_PORT));
        } catch (IOException e) {
            throw new IllegalStateException("RF module simulator failed to bind to port " + SERVER_PORT, e);
        }
    }

    private void acceptClient() {
        try {
            if (!waitingForClientLogged) {
                Logger.printlnGlobal("[rf_module_simulator_thread] Waiting for connection...");
                waitingForClientLogged = true;
            }
            clientSocket = serverSocket.accept();
            clientSocket.setSoTimeout(READ_TIMEOUT_MS);
            waitingForClientLogged = false;
            Logger.printlnGlobal("=================================================================");
            Logger.printlnGlobal("[rf_module_simulator_thread] New client connected from "
                + clientSocket.getInetAddress().getHostAddress());
            Logger.printlnGlobal("=================================================================");
        } catch (SocketTimeoutException e) {
            // Continue polling while the daemon thread is alive.
        } catch (IOException e) {
            Logger.printlnGlobal("[rf_module_simulator_thread] Client acceptance error: " + e.getMessage());
            closeClient();
            sleepQuietly(IDLE_SLEEP_MS);
        }
    }

    private int recvMessage() {
        try {
            byte[] incomingMessage = new byte[BUFFER_SIZE];
            InputStream input = clientSocket.getInputStream();
            int size = input.read(incomingMessage);

            if (size < 0) {
                Logger.printlnGlobal("[rf_module_simulator_thread] Connection closed. Restarting");
                closeClient();
                return 0;
            }

            if (size == 0) {
                return 0;
            }

            Logger.printlnGlobal(String.format("[rf_module_simulator_thread] Received %d bytes of data", size));
            VRX vrx = lookupVrx();
            if (vrx != null) {
                vrx.enqueueRadioPacket(Arrays.copyOf(incomingMessage, size));
            }
            return size;
        } catch (SocketTimeoutException e) {
            return 0;
        } catch (IOException e) {
            Logger.printlnGlobal("[rf_module_simulator_thread] recv error, closing socket: " + e.getMessage());
            closeClient();
            return -1;
        }
    }

    private VRX lookupVrx() {
        Device device = deviceManager.findDevice("VRX");
        if (device instanceof VRX vrx) {
            return vrx;
        }
        return null;
    }

    private UTX lookupUtx() {
        Device device = deviceManager.findDevice("UTX");
        if (device instanceof UTX utx) {
            return utx;
        }
        return null;
    }

    private void sendMessage() {
        if (clientSocket == null || clientSocket.isClosed()) {
            return;
        }

        UTX utx = lookupUtx();
        if (utx == null) {
            return;
        }

        byte[] packet = utx.dequeueOutgoingRadioPacket();
        if (packet == null || packet.length == 0) {
            return;
        }

        Logger.printlnGlobal("[rf_module_simulator_thread] Trying to transmit recorded packet via TCP...");
        try {
            OutputStream output = clientSocket.getOutputStream();
            output.write(packet);
            output.flush();
            Logger.printlnGlobal(String.format("[rf_module_simulator_thread] Transmitted %d bytes of data", packet.length));
        } catch (IOException e) {
            Logger.printlnGlobal("[rf_module_simulator_thread] Transmission FAILED! " + e.getMessage());
            closeClient();
        }
    }

    private void closeClient() {
        if (clientSocket == null) {
            return;
        }
        try {
            clientSocket.close();
        } catch (IOException e) {
            Logger.printlnGlobal("[rf_module_simulator_thread] Error closing client socket: " + e.getMessage());
        } finally {
            clientSocket = null;
        }
    }

    private void closeServer() {
        if (serverSocket == null) {
            return;
        }
        try {
            serverSocket.close();
        } catch (IOException e) {
            Logger.printlnGlobal("[rf_module_simulator_thread] Error closing server socket: " + e.getMessage());
        } finally {
            serverSocket = null;
        }
    }

    private static void sleepQuietly(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
