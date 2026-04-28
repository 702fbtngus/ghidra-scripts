package helper;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;

public class ProjectManager extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args == null || args.length == 0) {
            println("Usage:");
            println("  list");
            println("  exists <filename>");
            println("  delete <filename>");
            println("  copy <src> <dst>");
            return;
        }

        Project project = state.getProject();
        if (project == null) {
            printerr("No project loaded.");
            return;
        }

        DomainFolder root = project.getProjectData().getRootFolder();

        if ("list".equalsIgnoreCase(args[0])) {
            for (DomainFile f : root.getFiles()) {
                println(f.getName());
            }
            return;
        }

        if ("exists".equalsIgnoreCase(args[0])) {
            if (args.length < 2) {
                printerr("exists requires <filename>");
                return;
            }

            String name = args[1];
            println(root.getFile(name) != null ? "true" : "false");
            return;
        }

        if ("delete".equalsIgnoreCase(args[0])) {
            if (args.length < 2) {
                printerr("delete requires <filename>");
                return;
            }

            String name = args[1];
            DomainFile f = root.getFile(name);

            if (f == null) {
                println("File not found, nothing deleted: " + name);
                return;
            }

            println("Deleting: " + name);
            f.delete();
            println("Deleted.");
            return;
        }

        if ("copy".equalsIgnoreCase(args[0])) {
            if (args.length < 3) {
                printerr("copy requires <src> <dst>");
                return;
            }

            String srcName = args[1];
            String dstName = args[2];
            if (srcName.equals(dstName)) {
                throw new IllegalArgumentException("Source and destination names must differ.");
            }

            DomainFile src = root.getFile(srcName);
            if (src == null) {
                throw new IllegalArgumentException("Source file not found: " + srcName);
            }

            if (root.getFile(dstName) != null) {
                throw new IllegalArgumentException("Destination already exists: " + dstName);
            }

            Object consumer = new Object();
            DomainObject copyObject = null;
            try {
                copyObject = src.getReadOnlyDomainObject(
                    consumer,
                    DomainFile.DEFAULT_VERSION,
                    monitor
                );
                DomainFile copied = root.createFile(dstName, copyObject, monitor);
                println("Copied: " + srcName + " -> " + copied.getName());
            } finally {
                if (copyObject != null) {
                    copyObject.release(consumer);
                }
            }
            return;
        }

        printerr("Unknown command: " + args[0]);
    }
}
