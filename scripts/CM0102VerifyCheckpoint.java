// Read-only verification after restoring the standalone database archive.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102VerifyCheckpoint extends GhidraScript {
    private void require(boolean ok,String message) throws Exception {
        if(!ok)throw new Exception("Checkpoint verification failed: "+message);
    }
    public void run() throws Exception {
        JsonObject expected=JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonObject();
        require(expected.get("sha256").getAsString().equals(currentProgram.getExecutableSHA256()),"input hash");
        int functions=0,labels=0,types=0,fields=0,signatures=0,comments=0;
        for(JsonElement element:expected.getAsJsonArray("functions")) {
            JsonObject row=element.getAsJsonObject();
            Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row.get("address").getAsString(),16)));
            require(f!=null&&f.getName().equals(row.get("name").getAsString()),"function "+row);
            String actualComment=f.getComment();
            if(row.has("comment")) {
                if(row.get("comment").isJsonNull())require(actualComment==null||actualComment.isBlank(),"function comment null "+row);
                else require(row.get("comment").getAsString().equals(actualComment),"function comment exact "+row);
            } else require(actualComment!=null&&!actualComment.isBlank(),"function comment "+row);
            if(row.has("return_bytes"))require(f.getReturnType().getLength()==row.get("return_bytes").getAsInt(),"return width "+row);
            functions++;
        }
        for(JsonElement element:expected.getAsJsonArray("labels")) {
            JsonObject row=element.getAsJsonObject();boolean found=false;
            for(var symbol:currentProgram.getSymbolTable().getSymbols(toAddr(Long.parseLong(row.get("address").getAsString(),16))))
                if(symbol.getName().equals(row.get("name").getAsString()))found=true;
            require(found,"label "+row);labels++;
        }
        for(JsonElement element:expected.getAsJsonArray("partial_data_types")) {
            JsonObject row=element.getAsJsonObject();
            DataType dt=currentProgram.getDataTypeManager().getDataType(row.get("path").getAsString());
            require(dt instanceof Structure,"structure "+row.get("path"));
            Structure structure=(Structure)dt;
            require(structure.getLength()==row.get("bytes").getAsInt(),"structure size "+dt.getName());
            for(JsonElement field:row.getAsJsonArray("fields")) {
                JsonObject spec=field.getAsJsonObject();
                DataTypeComponent component=structure.getComponentAt(spec.get("offset").getAsInt());
                require(component!=null&&component.getOffset()==spec.get("offset").getAsInt()&&
                    component.getLength()==spec.get("bytes").getAsInt()&&
                    spec.get("name").getAsString().equals(component.getFieldName()),"field "+dt.getName()+" "+spec);
                fields++;
            }
            types++;
        }
        for(JsonElement element:expected.getAsJsonArray("code_signatures")) {
            JsonObject row=element.getAsJsonObject();String hex=row.get("hex").getAsString();
            byte[] actual=new byte[hex.length()/2];
            currentProgram.getMemory().getBytes(toAddr(Long.parseLong(row.get("address").getAsString(),16)),actual);
            require(HexFormat.of().formatHex(actual).equals(hex),"code signature "+row.get("address"));signatures++;
        }
        if(expected.has("code_comments"))for(JsonElement element:expected.getAsJsonArray("code_comments")){
            JsonObject row=element.getAsJsonObject();String note=currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT,toAddr(Long.parseLong(row.get("address").getAsString(),16)));
            require(row.get("text").getAsString().equals(note),"code comment "+row);comments++;
        }
        JsonObject receipt=new JsonObject();receipt.addProperty("status","passed");
        receipt.addProperty("mode","restored archive opened read-only; no reanalysis");
        receipt.addProperty("sha256",currentProgram.getExecutableSHA256());
        receipt.addProperty("named_functions_and_comments",functions);receipt.addProperty("global_labels",labels);
        receipt.addProperty("partial_structures",types);receipt.addProperty("structure_fields",fields);
        receipt.addProperty("original_code_signatures",signatures);
        receipt.addProperty("code_comments",comments);
        receipt.addProperty("total_function_symbols",currentProgram.getFunctionManager().getFunctionCount());
        Files.writeString(Paths.get(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
        println(receipt.toString());
    }
}
