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

    // 仅使用两个 payload：' 与 ''
    private static final String[] SQL_INJECTION_PAYLOADS = {
            "'",
            "''"
    };

    private static final String[] SQL_ERROR_KEYWORDS = {
            "syntax error", "near", "unexpected token", "SQL command", "ORA-", "Error Code:", "SQL syntax", "use near"
    };

    // 解析 URL 中的查询参数
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

    // 解析 POST 请求 body 中的参数（假设为 x-www-form-urlencoded 格式）
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

    // 将 payload 追加到 URL 中指定参数的值后面
    private static String injectPayloadIntoUrl(String url, String key, String payload) throws URISyntaxException {
        URI uri = new URI(url);
        String query = uri.getQuery();
        if (query == null) {
            return uri.getPath() + "?" + key + "=" + payload;
        }
        String[] pairs = query.split("&");
        StringBuilder newQuery = new StringBuilder();
        for (String pair : pairs) {
            if (pair.startsWith(key + "=")) {
                int idx = pair.indexOf("=");
                String originalValue = "";
                if (idx != -1 && pair.length() > idx + 1) {
                    originalValue = pair.substring(idx + 1);
                }
                newQuery.append(key)
                        .append("=")
                        .append(originalValue)
                        .append(payload)
                        .append("&");
            } else {
                newQuery.append(pair).append("&");
            }
        }
        if (newQuery.length() > 0 && newQuery.charAt(newQuery.length() - 1) == '&') {
            newQuery.deleteCharAt(newQuery.length() - 1);
        }
        return uri.getPath() + "?" + newQuery;
    }

    // 将 payload 追加到 POST 请求 body 中指定参数的值后面
    private static String injectPayloadIntoPostBody(String body, String key, String payload) {
        Map<String, String> params = parseQueryParametersBody(body);
        if (params.isEmpty()) {
            return body;
        }
        StringBuilder newBody = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().equals(key)) {
                newBody.append(entry.getKey())
                        .append("=")
                        .append(entry.getValue())
                        .append(payload)
                        .append("&");
            } else {
                newBody.append(entry.getKey())
                        .append("=")
                        .append(entry.getValue())
                        .append("&");
            }
        }
        if (newBody.length() > 0) {
            newBody.deleteCharAt(newBody.length() - 1);
        }
        return newBody.toString();
    }

    // 将 payload 追加到 Cookie 中指定 cookie 的值后面
    private static String injectPayloadIntoCookie(String cookieHeader, String targetCookie, String payload) {
        String[] cookieParts = cookieHeader.split(";");
        StringBuilder newCookieHeader = new StringBuilder();
        for (String part : cookieParts) {
            String trimmedPart = part.trim();
            int eqIndex = trimmedPart.indexOf("=");
            if (eqIndex > 0) {
                String name = trimmedPart.substring(0, eqIndex);
                String value = trimmedPart.substring(eqIndex + 1);
                if (name.equals(targetCookie)) {
                    newCookieHeader.append(name).append("=").append(value).append(payload);
                } else {
                    newCookieHeader.append(trimmedPart);
                }
            } else {
                newCookieHeader.append(trimmedPart);
            }
            newCookieHeader.append("; ");
        }
        if(newCookieHeader.length() >= 2) {
            newCookieHeader.setLength(newCookieHeader.length() - 2);
        }
        return newCookieHeader.toString();
    }

    // 判断是否为 Session Cookie，不进行检测
    private static boolean isSessionCookie(String cookieName) {
        String lower = cookieName.toLowerCase();
        return lower.contains("session") || lower.contains("phpsessid") || lower.contains("aspessionid") || lower.contains("jsessionid");
    }

    // 发送 HTTP 请求，检测 SQL 注入，并增加对 Cookie 中非 Session Cookie 的检测
    public HashMap<HttpRequest, HttpResponse> SqlDetection() throws InterruptedException {
        HashMap<HttpRequest, HttpResponse> requestHttpResponseMap = new HashMap<>();
        try {
            // 针对 URL/参数的检测（GET 请求）
            if (httpRequest.method().equalsIgnoreCase("GET")) {
                Map<String, String> params = parseQueryParametersUrl(baseUrl);
                if (!params.isEmpty()) {
                    for (Map.Entry<String, String> entry : params.entrySet()) {
                        String key = entry.getKey();
                        String payloadA = SQL_INJECTION_PAYLOADS[0];
                        String payloadB = SQL_INJECTION_PAYLOADS[1];
                        String urlPayloadA = URLEncoder.encode(payloadA);
                        String urlPayloadB = URLEncoder.encode(payloadB);
                        String injectedUrlPathA = injectPayloadIntoUrl(baseUrl, key, urlPayloadA);
                        String injectedUrlPathB = injectPayloadIntoUrl(baseUrl, key, urlPayloadB);
                        HttpRequest sqlRequestA = httpRequest.withPath(injectedUrlPathA).withBody("");
                        HttpRequest sqlRequestB = httpRequest.withPath(injectedUrlPathB).withBody("");
                        HttpResponse sqlResponseA = montoyaApi.http().sendRequest(sqlRequestA).response();
                        HttpResponse sqlResponseB = montoyaApi.http().sendRequest(sqlRequestB).response();
                        int lengthA = sqlResponseA.bodyToString().length();
                        int lengthB = sqlResponseB.bodyToString().length();
                        // 若响应长度不一致或响应中包含 SQL 错误，则记录该请求
                        if (sqlResponseA.statusCode() == 200 && sqlResponseB.statusCode() == 200 &&
                                (lengthA != lengthB || containsSQLError(sqlResponseA.bodyToString()))) {
                            int diff = Math.abs(lengthA - lengthB);
                            HttpRequest modifiedRequestA = sqlRequestA.withHeader("X-Length-Diff", String.valueOf(diff));
                            HttpRequest modifiedRequestB = sqlRequestB.withHeader("X-Length-Diff", String.valueOf(diff));
                            requestHttpResponseMap.put(modifiedRequestA, sqlResponseA);
                            requestHttpResponseMap.put(modifiedRequestB, sqlResponseB);
                        }
                        Thread.sleep(1);
                    }
                }
            }
            // 针对参数的检测（POST 请求）
            if (httpRequest.method().equalsIgnoreCase("POST")) {
                String originalBody = httpRequest.bodyToString();
                Map<String, String> params = parseQueryParametersBody(originalBody);
                if (!params.isEmpty()) {
                    for (Map.Entry<String, String> entry : params.entrySet()) {
                        String key = entry.getKey();
                        String payloadA = SQL_INJECTION_PAYLOADS[0];
                        String payloadB = SQL_INJECTION_PAYLOADS[1];
                        String urlPayloadA = URLEncoder.encode(payloadA);
                        String urlPayloadB = URLEncoder.encode(payloadB);
                        String injectedBodyA = injectPayloadIntoPostBody(originalBody, key, urlPayloadA);
                        String injectedBodyB = injectPayloadIntoPostBody(originalBody, key, urlPayloadB);
                        HttpRequest sqlRequestA = httpRequest.withBody(injectedBodyA);
                        HttpRequest sqlRequestB = httpRequest.withBody(injectedBodyB);
                        HttpResponse sqlResponseA = montoyaApi.http().sendRequest(sqlRequestA).response();
                        HttpResponse sqlResponseB = montoyaApi.http().sendRequest(sqlRequestB).response();
                        int lengthA = sqlResponseA.bodyToString().length();
                        int lengthB = sqlResponseB.bodyToString().length();
                        if (sqlResponseA.statusCode() == 200 && sqlResponseB.statusCode() == 200 &&
                                (lengthA != lengthB || containsSQLError(sqlResponseA.bodyToString()))) {
                            int diff = Math.abs(lengthA - lengthB);
                            HttpRequest modifiedRequestA = sqlRequestA.withHeader("X-Length-Diff", String.valueOf(diff));
                            HttpRequest modifiedRequestB = sqlRequestB.withHeader("X-Length-Diff", String.valueOf(diff));
                            requestHttpResponseMap.put(modifiedRequestA, sqlResponseA);
                            requestHttpResponseMap.put(modifiedRequestB, sqlResponseB);
                        }
                        Thread.sleep(1);
                    }
                }
            }
            // 针对 Cookie 的检测（适用于 GET 和 POST 请求）
            // 直接获取 Cookie 字符串并解析
            String originalCookieHeader = httpRequest.headerValue("Cookie");
            if (originalCookieHeader != null && !originalCookieHeader.isEmpty()) {
                String[] cookies = originalCookieHeader.split(";");
                for (String cookie : cookies) {
                    cookie = cookie.trim();
                    int eqIndex = cookie.indexOf("=");
                    if (eqIndex > 0) {
                        String name = cookie.substring(0, eqIndex);
                        if (isSessionCookie(name)) {
                            continue;
                        }
                        String payloadA = SQL_INJECTION_PAYLOADS[0];
                        String payloadB = SQL_INJECTION_PAYLOADS[1];
                        String encodedPayloadA = URLEncoder.encode(payloadA);
                        String encodedPayloadB = URLEncoder.encode(payloadB);
                        // 分别构造两个注入后的 Cookie 头
                        String injectedCookieHeaderA = injectPayloadIntoCookie(originalCookieHeader, name, encodedPayloadA);
                        String injectedCookieHeaderB = injectPayloadIntoCookie(originalCookieHeader, name, encodedPayloadB);
                        HttpRequest requestCookieA = httpRequest.withHeader("Cookie", injectedCookieHeaderA);
                        HttpRequest requestCookieB = httpRequest.withHeader("Cookie", injectedCookieHeaderB);
                        HttpResponse responseCookieA = montoyaApi.http().sendRequest(requestCookieA).response();
                        HttpResponse responseCookieB = montoyaApi.http().sendRequest(requestCookieB).response();
                        int lenA = responseCookieA.bodyToString().length();
                        int lenB = responseCookieB.bodyToString().length();
                        if (responseCookieA.statusCode() == 200 && responseCookieB.statusCode() == 200 &&
                                (lenA != lenB || containsSQLError(responseCookieA.bodyToString()))) {
                            int diff = Math.abs(lenA - lenB);
                            requestCookieA = requestCookieA.withHeader("X-Length-Diff", String.valueOf(diff));
                            requestCookieB = requestCookieB.withHeader("X-Length-Diff", String.valueOf(diff));
                            requestHttpResponseMap.put(requestCookieA, responseCookieA);
                            requestHttpResponseMap.put(requestCookieB, responseCookieB);
                        }
                        Thread.sleep(1);
                    }
                }
            }
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return requestHttpResponseMap;
    }

    // 检查响应中是否包含 SQL 错误信息
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
