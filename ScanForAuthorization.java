import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScanForAuthorization {
    private static String baseUrl;
    private static HttpRequest httpRequest;
    private static MontoyaApi montoyaApi;

    public ScanForAuthorization(String baseUrl, HttpRequest httpRequest, MontoyaApi montoyaApi) {
        this.baseUrl = baseUrl;
        this.httpRequest = httpRequest;
        this.montoyaApi = montoyaApi;
    }


    public boolean scanForAuthorizationVulnerabilities() {
        try {

            String originalResponse = httpRequest.bodyToString();
            //System.out.println(originalResponse);
            Map<String, List<String>> modifiedParams = modifyParameters();
            for (Map.Entry<String, List<String>> entry : modifiedParams.entrySet()) {
                String modifiedUrl = entry.getKey();
                List<String> modifiedValues = entry.getValue();

                for (String value : modifiedValues) {
                    String testUrl = modifiedUrl.replace("{{VALUE}}", value);
                    URL urlString = new URL(testUrl);
                    String testPath = urlString.getPath();
                    HttpRequest testRequest = httpRequest.withPath(testPath).withBody("");
                    HttpResponse testResponse = montoyaApi.http().sendRequest(testRequest).response();
                    if (!testResponse.equals(originalResponse) && testResponse.statusCode() != 403 && testResponse.statusCode() != 404 && testResponse.statusCode() != 500) {
                        return true;
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }


    public static Map<String, List<String>> modifyParameters() {
        Map<String, List<String>> modifiedUrls = new HashMap<>();
        String[] testValues = {"test", "admin", "super", "abc", "test123"};

        // 找到URL中的参数
        int queryParamsStart = baseUrl.indexOf('?');
        if (queryParamsStart != -1) {
            String[] params = baseUrl.substring(queryParamsStart + 1).split("&");
            for (String param : params) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2) {
                    String key = keyValue[0];
                    String value = keyValue[1];

                    if (isNumeric(value)) {
                        int numericValue = Integer.parseInt(value);
                        String[] numericTestValues = {String.valueOf(numericValue + 1), String.valueOf(numericValue - 1)};

                        for (String testValue : numericTestValues) {
                            String modifiedUrl = baseUrl.replace(value, "{{VALUE}}");
                            modifiedUrls.computeIfAbsent(modifiedUrl, k -> new ArrayList<>()).add(testValue);
                        }
                    } else {
                        for (String testValue : testValues) {
                            String modifiedUrl = baseUrl.replace(value, "{{VALUE}}");
                            modifiedUrls.computeIfAbsent(modifiedUrl, k -> new ArrayList<>()).add(testValue);
                        }
                    }
                }
            }
        }

        return modifiedUrls;
    }

    private static boolean isNumeric(String str) {
        try {
            Integer.parseInt(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
