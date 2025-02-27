
import burp.api.montoya.http.message.HttpRequestResponse;

public class SourceLogEntry {
    private int id;
    private String tool;
    private String myHash;
    private String vulnState;
    private int bodyLength;
    private HttpRequestResponse httpRequestResponse;
    private String httpService;
    private String method;
    private String path;
    private int status;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTool() {
        return tool;
    }

    public void setTool(String tool) {
        this.tool = tool;
    }

    public String getMyHash() {
        return myHash;
    }

    public void setMyHash(String myHash) {
        this.myHash = myHash;
    }

    public String getVulnState() {
        return vulnState;
    }

    public void setVulnState(String vulnState) {
        this.vulnState = vulnState;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public void setBodyLength(int bodyLength) {
        this.bodyLength = bodyLength;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

    public void setHttpRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }
    public String getHttpService() {
        return httpService;
    }

    public void setHttpService(String httpService) {
        this.httpService = httpService;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public int getStatus() {
        return status;
    }
    public void setStatus(int status) {
        this.status = status;
    }

    public SourceLogEntry(int id, String tool, String myHash, String vulnState, int bodyLength, HttpRequestResponse httpRequestResponse, String httpService, String path, int status) {
        this.id = id;
        this.tool = tool;
        this.myHash = myHash;
        this.vulnState = vulnState;
        this.bodyLength = bodyLength;
        this.httpRequestResponse = httpRequestResponse;
        this.httpService = httpService;
        this.path = path;
        this.status = status;
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SourceLogEntry comSource = (SourceLogEntry) o;
        return id == comSource.id;
    }
}