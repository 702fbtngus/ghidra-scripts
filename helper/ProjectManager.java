package helper;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;

public class ProjectManager extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args == null || args.length == 0) {
            println("Usage:");
            println("  list");
            println("  delete <filename>");
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

        if ("delete".equalsIgnoreCase(args[0])) {
            if (args.length < 2) {
                printerr("delete requires <filename>");
                return;
            }

            String name = args[1];
            DomainFile f = root.getFile(name);

            if (f == null) {
                printerr("File not found: " + name);
                return;
            }

            println("Deleting: " + name);
            f.delete();
            println("Deleted.");
            return;
        }

        printerr("Unknown command: " + args[0]);
    }
}