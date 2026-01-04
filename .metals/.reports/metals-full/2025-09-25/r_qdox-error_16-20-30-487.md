error id: file://<WORKSPACE>/CollectBranches.java
file://<WORKSPACE>/CollectBranches.java
### com.thoughtworks.qdox.parser.ParseException: syntax error @[58,1]

error in qdox parser
file content:
```java
offset: 2005
uri: file://<WORKSPACE>/CollectBranches.java
text:
```scala
// Ghidra Java script: print pcode ops starting from program entrypoint
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.util.*;
import java.util.function.Consumer;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

// CollectBranches.java

public class CollectBranches extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(true); // 전체 프로그램 순회
        
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            FlowType ft = instr.getFlowType();
            
            // branch 계열 판별
            if (ft.isJump() || ft.isConditional() || ft.isTerminal() || ft.isCall()) {
            if (ft.isConditional()) {
                Address[] dests = instr.getFlows();
                Address fallthrough = instr.getFallThrough();
                // if (dests.length >= 2) {
                    
                    StringBuilder sb = new StringBuilder();
                    sb.append(instr.getAddress()).append(": ").append(instr);
                    sb.append(" -> [");
                        for (int i = 0; i < dests.length; i++) {
                            sb.append(dests[i]);
                            if (i < dests.length - 1) sb.append(", ");
                        }
                        sb.append("]");
                        
                        println(sb.toString());
                    // fallthrough도 추가
                    if (fallthrough != null) {
                        sb.append(fallthrough);
                    }
                // }
            }
        }
    }
}
@@
```

```



#### Error stacktrace:

```
com.thoughtworks.qdox.parser.impl.Parser.yyerror(Parser.java:2025)
	com.thoughtworks.qdox.parser.impl.Parser.yyparse(Parser.java:2147)
	com.thoughtworks.qdox.parser.impl.Parser.parse(Parser.java:2006)
	com.thoughtworks.qdox.library.SourceLibrary.parse(SourceLibrary.java:232)
	com.thoughtworks.qdox.library.SourceLibrary.parse(SourceLibrary.java:190)
	com.thoughtworks.qdox.library.SourceLibrary.addSource(SourceLibrary.java:94)
	com.thoughtworks.qdox.library.SourceLibrary.addSource(SourceLibrary.java:89)
	com.thoughtworks.qdox.library.SortedClassLibraryBuilder.addSource(SortedClassLibraryBuilder.java:162)
	com.thoughtworks.qdox.JavaProjectBuilder.addSource(JavaProjectBuilder.java:174)
	scala.meta.internal.mtags.JavaMtags.indexRoot(JavaMtags.scala:49)
	scala.meta.internal.metals.SemanticdbDefinition$.foreachWithReturnMtags(SemanticdbDefinition.scala:99)
	scala.meta.internal.metals.Indexer.indexSourceFile(Indexer.scala:489)
	scala.meta.internal.metals.Indexer.$anonfun$reindexWorkspaceSources$3(Indexer.scala:587)
	scala.meta.internal.metals.Indexer.$anonfun$reindexWorkspaceSources$3$adapted(Indexer.scala:584)
	scala.collection.IterableOnceOps.foreach(IterableOnce.scala:619)
	scala.collection.IterableOnceOps.foreach$(IterableOnce.scala:617)
	scala.collection.AbstractIterator.foreach(Iterator.scala:1306)
	scala.meta.internal.metals.Indexer.reindexWorkspaceSources(Indexer.scala:584)
	scala.meta.internal.metals.MetalsLspService.$anonfun$onChange$2(MetalsLspService.scala:916)
	scala.runtime.java8.JFunction0$mcV$sp.apply(JFunction0$mcV$sp.scala:18)
	scala.concurrent.Future$.$anonfun$apply$1(Future.scala:687)
	scala.concurrent.impl.Promise$Transformation.run(Promise.scala:467)
	java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)
	java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642)
	java.base/java.lang.Thread.run(Thread.java:1575)
```
#### Short summary: 

QDox parse error in file://<WORKSPACE>/CollectBranches.java