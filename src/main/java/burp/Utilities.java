package burp;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;

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

    public static IHttpRequestResponse makeRequest(IHttpRequestResponse requestResponse, String path) {
        IHttpService service = requestResponse.getHttpService();

        return callbacks.makeHttpRequest(service, buildRequest(requestResponse, path));
    }

    public static byte[] buildRequest(IHttpRequestResponse requestResponse, String path) {
        URL url = helpers.analyzeRequest(requestResponse).getUrl();

        URL targetURL = null;
        try {
            targetURL = new URL(url.getProtocol(), url.getHost(), url.getPort(), path);
        } catch (MalformedURLException e) {
            e.printStackTrace(Utilities.err);
        }

        return helpers.buildHttpRequest(targetURL);
    }

    public static int getStatus(IHttpRequestResponse requestResponse) {
        return helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
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
}
