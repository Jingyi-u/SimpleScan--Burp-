import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class SpringBootScan {
    private List<String> pathOfSpringBootError = new ArrayList<>(List.of(
            "api-docs",
            "actuator",
            "actuator/auditLog",
            "actuator/auditevents",
            "actuator/autoconfig",
            "actuator/beans",
            "actuator/caches",
            "actuator/conditions",
            "actuator/configurationMetadata",
            "actuator/configprops",
            "actuator/dump",
            "actuator/env",
            "actuator/events",
            "actuator/exportRegisteredServices",
            "actuator/features",
            "actuator/flyway",
            "actuator/health",
            "actuator/healthcheck",
            "actuator/httptrace",
            "actuator/hystrix.stream",
            "actuator/info",
            "actuator/integrationgraph",
            "actuator/jolokia",
            "actuator/logfile",
            "actuator/loggers",
            "actuator/loggingConfig",
            "actuator/liquibase",
            "actuator/metrics",
            "actuator/mappings",
            "actuator/scheduledtasks",
            "actuator/swagger-ui.html",
            "actuator/prometheus",
            "actuator/refresh",
            "actuator/registeredServices",
            "actuator/releaseAttributes",
            "actuator/resolveAttributes",
            "actuator/scheduledtasks",
            "actuator/sessions",
            "actuator/springWebflow",
            "actuator/sso",
            "actuator/ssoSessions",
            "actuator/statistics",
            "actuator/status",
            "actuator/threaddump",
            "actuator/trace",
            "actuator/env.css",
            "auditevents",
            "autoconfig",
            "api",
            "api.html",
            "api/actuator",
            "api/index.html",
            "api/swagger-ui.html",
            "api/v2/api-docs",
            "api/v2;%0A/api-docs",
            "api/v2;%252Ftest/api-docs",
            "api-docs",
            "beans",
            "caches",
            "cloudfoundryapplication",
            "conditions",
            "configprops",
            "distv2/index.html",
            "docs",
            "druid/index.html",
            "druid/login.html",
            "druid/websession.html",
            "dubbo-provider/distv2/index.html",
            "dump",
            "entity/all",
            "env",
            "env.css",
            "env/(name)",
            "eureka",
            "flyway",
            "gateway/actuator",
            "gateway/actuator/auditevents",
            "gateway/actuator/beans",
            "gateway/actuator/conditions",
            "gateway/actuator/configprops",
            "gateway/actuator/env",
            "gateway/actuator/health",
            "gateway/actuator/httptrace",
            "gateway/actuator/hystrix.stream",
            "gateway/actuator/info",
            "gateway/actuator/jolokia",
            "gateway/actuator/logfile",
            "gateway/actuator/loggers",
            "gateway/actuator/mappings",
            "gateway/actuator/metrics",
            "gateway/actuator/scheduledtasks",
            "gateway/actuator/swagger-ui.html",
            "gateway/actuator/threaddump",
            "gateway/actuator/trace",
            "gateway/routes",
            "health",
            "httptrace",
            "hystrix",
            "info",
            "integrationgraph",
            "jolokia",
            "jolokia/list",
            "jeecg/swagger-ui",
            "jeecg/swagger/",
            "liquibase",
            "list",
            "logfile",
            "loggers",
            "liquibase",
            "metrics",
            "mappings",
            "monitor",
            "nacos",
            "prod-api/actuator",
            "prometheus",
            "refresh",
            "scheduledtasks",
            "sessions",
            "spring-security-oauth-resource/swagger-ui.html",
            "spring-security-rest/api/swagger-ui.html",
            "static/swagger.json",
            "sw/swagger-ui.html",
            "swagger",
            "swagger/codes",
            "swagger/index.html",
            "swagger/static/index.html",
            "swagger/swagger-ui.html",
            "swagger-dubbo/api-docs",
            "swagger-ui",
            "swagger-ui.html",
            "swagger-ui/html",
            "swagger-ui/index.html",
            "system/druid/index.html",
            "threaddump",
            "template/swagger-ui.html",
            "trace",
            "users",
            "user/swagger-ui.html",
            "version",
            "v1/swagger-resources",
            "v2/swagger-resources",
            "v1.1/swagger-ui.html",
            "v1.1;%0A/api-docs",
            "v1.2/swagger-ui.html",
            "v1.2;%0A/api-docs",
            "v1.3/swagger-ui.html",
            "v1.3;%0A/api-docs",
            "v1.4/swagger-ui.html",
            "v1.4;%0A/api-docs",
            "v1.5/swagger-ui.html",
            "v1.5;%0A/api-docs",
            "v1.6/swagger-ui.html",
            "v1.6;%0A/api-docs",
            "v1.7/swagger-ui.html",
            "v1.7;%0A/api-docs",
            "v1.8/swagger-ui.html",
            "v1.8;%0A/api-docs",
            "v1.9/swagger-ui.html",
            "v1.9;%0A/api-docs",
            "v2.0/swagger-ui.html",
            "v2.0;%0A/api-docs",
            "v2.1/swagger-ui.html",
            "v2.1;%0A/api-docs",
            "v2.2/swagger-ui.html",
            "v2.2;%0A/api-docs",
            "v2.3/swagger-ui.html",
            "v2.3;%0A/api-docs",
            "v1/swagger.json",
            "v2/swagger.json",
            "v3/swagger.json",
            "v2;%0A/api-docs",
            "v3;%0A/api-docs",
            "v2;%252Ftest/api-docs",
            "v3;%252Ftest/api-docs",
            "webpage/system/druid/index.html",
            " %20/swagger-ui.html"
    ));
    private String hashIco = "0488faca4c19046b94d07c3ee83cf9d6";
    private String icoPath = "favicon.ico";
    private String errorPath = "aabbccee";
    private  String baseUrl;
    private HttpRequest httpRequest;
    private MontoyaApi montoyaApi;

    public SpringBootScan(String baseUrl, HttpRequest httpRequest, MontoyaApi montoyaApi) {
        this.baseUrl = baseUrl;
        this.httpRequest = httpRequest;
        this.montoyaApi = montoyaApi;
    }


    public boolean  getIcoHash(){
        String icoUrl = baseUrl + this.icoPath;
        HttpRequest icoRequest = httpRequest.withPath(icoUrl).withBody("");
        HttpResponse icoResponse = montoyaApi.http().sendRequest(icoRequest).response();
        montoyaApi.logging().logToOutput(icoUrl);

        // 检查响应状态码
        if (icoResponse.statusCode() == 200) {
            // 获取响应体
            byte[] responseBody = icoResponse.body().getBytes();
            // 计算MD5哈希
            String hash = calculateMD5(responseBody);
            montoyaApi.logging().logToOutput(hash);
            if (hash.equals(hashIco)){
                return true;
            }
        }else {
            return false;
        }
        return false;
    }

    public boolean getPathError(){
        String errorUrl = baseUrl + this.errorPath;
        HttpRequest errorRequest = httpRequest.withPath(errorUrl).withBody("");
        HttpResponse errorResponse = montoyaApi.http().sendRequest(errorRequest).response();
        if (errorResponse.statusCode() == 200 && (errorResponse.bodyToString().contains("Whitelabel Error Page") || errorResponse.bodyToString().contains(" mapping for /error"))) {
               return true;
        }
        return false;
    }

    public HashMap<HttpRequest, HttpResponse> startPathScan() throws InterruptedException {
        HashMap<HttpRequest, HttpResponse> requestHttpResponseMap = new HashMap<>();
        //循环发送请求
        for (String path: pathOfSpringBootError){
            String url = baseUrl + path;
            HttpRequest pathRequest = httpRequest.withPath("/"+path).withMethod("GET").withBody("");

            HttpResponse pathResponse = montoyaApi.http().sendRequest(pathRequest).response();
            //montoyaApi.logging().logToOutput(url+"\n");
            //montoyaApi.logging().logToOutput(pathResponse.statusCode()+"\n");
            //requestHttpResponseMap.put(pathRequest, pathResponse);
            if (pathResponse.statusCode() == 200) {
                requestHttpResponseMap.put(pathRequest, pathResponse);
            }
            Thread.sleep(10);
        }
        return requestHttpResponseMap;
    }

    private String calculateMD5(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(data);
            String hash = bytesToHex(hashBytes);

            if(hashIco.equals(hash)){
                return hash;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
        return "";
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
