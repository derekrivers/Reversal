// Add three original switch-case blocks omitted from Ghidra's inferred body.
// Apply only to a preserved checkpoint-16 project after independent review.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;

public class CM0102CorrectMatchBody17 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final long ENTRY=0x006f09f0L, FIRST=0x006f1639L, LAST=0x006f164dL;
 private static final long[] STARTS={0x006f1639L,0x006f163eL,0x006f1640L,0x006f1645L,0x006f1647L,0x006f164cL};
 private static final String[] TEXT={"MOV EBX,0x1ff6","JMP 0x006f1670","MOV EBX,0x1ff7","JMP 0x006f1670","MOV EBX,0x1ff9","JMP 0x006f1670"};
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Body correction precondition: "+what);}
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==1,"Use OUTPUT_JSON");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(ENTRY));
  require(f!=null&&"FUN_006f09f0".equals(f.getName()),"old function entry/name");
  require(f.getBody().contains(toAddr(0x006f1632L))&&f.getBody().contains(toAddr(0x006f164eL))&&f.getBody().contains(toAddr(0x006f1670L)),"known body neighbors");
  require(!f.getBody().intersects(toAddr(FIRST),toAddr(LAST)),"range already owned");
  require(f.getBody().getNumAddresses()==14526,"old body size");
  long[] targets={0x006f1647L,0x006f1640L,0x006f164eL,0x006f1639L};
  for(int i=0;i<targets.length;i++)
   require(Integer.toUnsignedLong(currentProgram.getMemory().getInt(toAddr(0x006f4354L+4L*i)))==targets[i],"switch table index "+i);
  for(int i=0;i<STARTS.length;i++){
   var a=toAddr(STARTS[i]);Instruction ins=currentProgram.getListing().getInstructionAt(a);
   require(ins!=null&&TEXT[i].equals(ins.toString()),"instruction "+Long.toHexString(STARTS[i]));
   require(ins.getLength()==(i%2==0?5:2),"instruction length "+i);
   require(currentProgram.getFunctionManager().getFunctionContaining(a)==null,"unowned instruction "+i);
  }
  AddressSet body=new AddressSet(f.getBody());body.addRange(toAddr(FIRST),toAddr(LAST));
  require(body.getNumAddresses()==14547,"new body size");
  int tx=currentProgram.startTransaction("Investigation 17 switch body closure");boolean commit=false;
  try {f.setBody(body);commit=true;} finally {currentProgram.endTransaction(tx,commit);}
  require(f.getBody().getNumAddresses()==14547,"saved body size");
  for(long start:STARTS)require(f.getBody().contains(toAddr(start)),"saved case instruction");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("function","006f09f0");
  receipt.addProperty("old_body_bytes",14526);receipt.addProperty("new_body_bytes",14547);
  receipt.addProperty("added_range","006f1639..006f164d");receipt.addProperty("added_instruction_starts",STARTS.length);
  receipt.addProperty("scope","Function-body membership only; original instructions unchanged.");
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Corrected 006f09f0 body membership: +21 original bytes");
 }
}
