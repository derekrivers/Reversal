// Read-only local assembly/pseudocode export. Keep generated bulk code out of Git.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
public class CM0102ExportSelected extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();Path out=Paths.get(args[0]);Files.createDirectories(out);
  DecompInterface dc=new DecompInterface();dc.openProgram(currentProgram);
  try {for(String address:args[1].split(",")) {
   Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16)));
   if(f==null)throw new Exception("Missing function: "+address);
   StringBuilder asm=new StringBuilder();
   for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true))asm.append(ins.getAddress()+"  "+ins+"\n");
   Files.writeString(out.resolve(address+".asm"),asm);
   DecompileResults result=dc.decompileFunction(f,60,monitor);
   if(!result.decompileCompleted())throw new Exception(result.getErrorMessage());
   Files.writeString(out.resolve(address+".c"),"/* Inferred pseudocode; verify widths and calling convention in assembly. */\n"+result.getDecompiledFunction().getC());
  }} finally {dc.dispose();}
 }
}
