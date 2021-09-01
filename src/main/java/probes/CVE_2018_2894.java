package probes;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.Utilities;
import burp.WebLogicIssue;

public class CVE_2018_2894 extends Probe {
    private static final String NAME = "CVE-2018-2894";
    private static final String SEVERITY = "High";
    private static String detail = "WebLogic has a file upload vulnerability, but you need to upload the shell manually.";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String path1 = "/ws_utc/begin.do";
        String path2 = "/ws_utc/config.do";

        IHttpRequestResponse beginReqResp = Utilities.makeRequest(requestResponse, path1);
        IHttpRequestResponse configReqResp = Utilities.makeRequest(requestResponse, path2);

        if (Utilities.getStatus(beginReqResp) == 200) {
            detail = detail + "<br/><br/>" + Utilities.helpers.bytesToString(beginReqResp.getResponse());
            return new WebLogicIssue(beginReqResp, NAME, detail, SEVERITY);
        } else if (Utilities.getStatus(configReqResp) == 200) {
            detail = detail + "<br/><br/>" + Utilities.helpers.bytesToString(configReqResp.getResponse());
            return new WebLogicIssue(configReqResp, NAME, detail, SEVERITY);
        } else
            return null;
    }
}
