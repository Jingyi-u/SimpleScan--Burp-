import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.responses.HttpResponse;

public class MyFilterRequest {

    public static boolean fromProxy(HttpResponseReceived httpResponseReceived){
        return httpResponseReceived.toolSource().isFromTool(ToolType.PROXY);
    }
    public static boolean fromRepeater(HttpResponseReceived httpResponseReceived){
        return httpResponseReceived.toolSource().isFromTool(ToolType.REPEATER);
    }
}
