import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindSecret {

//    private static String baseUrl;
//    private static HttpRequest httpRequest;
//    private static MontoyaApi montoyaApi;
//
//    public FindSecret(String baseUrl, HttpRequest httpRequest, MontoyaApi montoyaApi) {
//        this.baseUrl = baseUrl;
//        this.httpRequest = httpRequest;
//        this.montoyaApi = montoyaApi;
//    }

        // 身份证号正则表达式
//        private static final String ID_CARD_REGEX = "(^\\d{15}$)|(^\\d{18}$)|(^\\d{17}(\\d|X|x)$)";
//        // 手机号正则表达式
//        private static final String PHONE_REGEX = "^1[3-9]\\d{9}$";
//        // 邮箱地址正则表达式
//        private static final String EMAIL_REGEX = "^[a-zA-Z0-9_]+@[a-zA-Z0-9]+(\\.[a-zA-Z]+)+$";
//        // 银行卡号正则表达式
//        private static final String BANK_CARD_REGEX = "^\\d{16,19}$";
//        // URL正则表达式
//        private static final String URL_REGEX = "^(http|https)://[\\w.-]+(\\.[\\w.-]+)+([/?].*)?$";


    public List<String> detectSensitiveInfo(String text, MontoyaApi montoyaApi) {
        List<String> results = new ArrayList<>();

        // 检测身份证号
        Pattern idCardPattern = Pattern.compile("(\\b\\d{15}\\b)|(\\b\\d{18}\\b)|(\\b\\d{17}(\\d|X|x)\\b)");
        Matcher idCardMatcher = idCardPattern.matcher(text);
        while (idCardMatcher.find()) {
            results.add("身份证号: " + idCardMatcher.group());
        }

        // 检测手机号
        Pattern phonePattern = Pattern.compile("\\b1[3-9]\\d{9}\\b");
        Matcher phoneMatcher = phonePattern.matcher(text);
        while (phoneMatcher.find()) {
            //montoyaApi.logging().logToOutput("33");
            results.add("手机号: " + phoneMatcher.group());
        }

        // 检测邮箱地址
        Pattern emailPattern = Pattern.compile("\\b[a-zA-Z0-9_]+@[a-zA-Z0-9]+(\\.[a-zA-Z]+)+\\b");
        Matcher emailMatcher = emailPattern.matcher(text);
        while (emailMatcher.find()) {
            //montoyaApi.logging().logToOutput("22");
            results.add("邮箱地址: " + emailMatcher.group());
        }

        // 检测银行卡号
        Pattern bankCardPattern = Pattern.compile("\\b\\d{16,19}\\b");
        Matcher bankCardMatcher = bankCardPattern.matcher(text);
        while (bankCardMatcher.find()) {
            results.add("银行卡号: " + bankCardMatcher.group());
        }

        // 检测URL
        Pattern urlPattern = Pattern.compile("\\b(http|https)://[\\w.-]+(\\.[\\w.-]+)+([/?].*)?\\b");
        Matcher urlMatcher = urlPattern.matcher(text);
        while (urlMatcher.find()) {
            results.add("URL: " + urlMatcher.group());
        }

        return results;
    }

//    HttpResponse response = montoyaApi.http().sendRequest(HttpRequest.httpRequest(baseUrl)).response();
//    String responseBody = response.bodyToString();
//    List<String> result = SensitiveInfoDetector.detectSensitiveInfo(responseBody);
}

