package burp;

import java.io.*;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class Utilities {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter out;
    public static PrintWriter err;
    public static IBurpCollaboratorClientContext collaborator;

    public Utilities(IBurpExtenderCallbacks callbacks) {
        Utilities.callbacks = callbacks;
        Utilities.helpers = callbacks.getHelpers();
        Utilities.out = new PrintWriter(callbacks.getStdout(), true);
        Utilities.err = new PrintWriter(callbacks.getStderr(), true);
        Utilities.collaborator = callbacks.createBurpCollaboratorClientContext();
    }

    public static IHttpRequestResponse makeGetRequest(IHttpService service, String path, HashMap<String, String> headers) {
        byte[] req = buildRequest(service, path);
        if (!headers.isEmpty()) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                req = replaceOrAddHeader(req, header.getKey(), header.getValue());
            }
        }
        return callbacks.makeHttpRequest(service, req);
    }

    public static IHttpRequestResponse makePostRequest(IHttpService service, String path, HashMap<String, String> headers, String data) {
        byte[] req = buildRequest(service, path);
        req = helpers.toggleRequestMethod(req);
        if (!headers.isEmpty()) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                req = replaceOrAddHeader(req, header.getKey(), header.getValue());
            }
        }
        return callbacks.makeHttpRequest(service, helpers.buildHttpMessage(
                helpers.analyzeRequest(req).getHeaders(),
                helpers.stringToBytes(data)
        ));
    }

    /**
     * 构建 GET 请求
     *
     * @param service 封装协议、主机名、端口
     * @param path    访问路径
     * @return 请求包内容
     */
    public static byte[] buildRequest(IHttpService service, String path) {
        URL targetURL = null;
        try {
            targetURL = new URL(
                    service.getProtocol(),
                    service.getHost(),
                    service.getPort(),
                    path
            );
        } catch (MalformedURLException e) {
            e.printStackTrace(Utilities.err);
        }
        return helpers.buildHttpRequest(targetURL);
    }

    public static int getStatus(IHttpRequestResponse requestResponse) {
        return helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
    }

    /**
     * 替换或者新增一个请求头
     *
     * @param req    待替换的请求包
     * @param header 请求头
     * @param value  请求头的值
     * @return 新的请求包
     */
    public static byte[] replaceOrAddHeader(byte[] req, String header, String value) {
        IRequestInfo reqInfo = helpers.analyzeRequest(req);
        boolean newHeader = true;
        // save body content
        int offset = reqInfo.getBodyOffset();
        byte[] body = new byte[req.length - offset];
        System.arraycopy(req, offset, body, 0, body.length);

        List<String> headers = reqInfo.getHeaders();
        // start from second item
        for (int i = 1; i < headers.size(); i++) {
            if (headers.get(i).startsWith(header)) {
                headers.set(i, header + ":" + value);
                newHeader = false;
            }
        }
        // is a new header
        if (newHeader) {
            headers.add(header + ":" + value);
        }
        return helpers.buildHttpMessage(headers, body);
    }

    public static String fetchInteraction(String pollPayload) {
        StringBuilder result = new StringBuilder();
        for (IBurpCollaboratorInteraction interaction : Utilities.collaborator.fetchCollaboratorInteractionsFor(pollPayload)) {
            // get DNS or HTTP query record
            result
                    .append("Receive a ").append(interaction.getProperty("type"))
                    .append(" query from ").append(interaction.getProperty("client_ip"))
                    .append(" at ").append(interaction.getProperty("time_stamp"))
                    .append("<br/>");
        }
        return result.toString();
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static Field getField(final Class<?> clazz, final String fieldName) throws Exception {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field;
    }

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
}
