package probes;

import burp.*;

public class Console extends Probe {
    private static final String NAME = "WebLogic console";
    private static final String SEVERITY = "Low";
    private static String detail = "WebLogic console address is exposed!";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String consolePath = "/console/login/LoginForm.jsp";

        IHttpRequestResponse checkReqResp = Utilities.makeRequest(requestResponse, consolePath);

        if (Utilities.getStatus(checkReqResp) == 200) {
            return new WebLogicIssue(checkReqResp, NAME, detail, SEVERITY);
        }

        return null;
    }
}
