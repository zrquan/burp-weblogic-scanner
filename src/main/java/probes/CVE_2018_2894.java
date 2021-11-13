package probes;

import burp.*;

// 仅探测可能存在文件上传漏洞的路径
public class CVE_2018_2894 extends Probe {
    private static final String NAME = "CVE-2018-2894";
    private static final String SEVERITY = "High";
    private static final String DESC = "File upload vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). Supported versions that are affected are 12.1.3.0, 12.2.1.2 and 12.2.1.3.";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String path1 = "/ws_utc/begin.do";
        String path2 = "/ws_utc/config.do";

        IHttpService service = requestResponse.getHttpService();
        IHttpRequestResponse beginReqResp = getReq(service, path1);
        IHttpRequestResponse configReqResp = getReq(service, path2);

        if (Utilities.getStatus(beginReqResp) == 200) {
            return new WebLogicIssue(beginReqResp, NAME, DESC, SEVERITY);
        } else if (Utilities.getStatus(configReqResp) == 200) {
            return new WebLogicIssue(configReqResp, NAME, DESC, SEVERITY);
        } else return null;
    }
}
