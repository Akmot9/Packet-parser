// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

// Produit le trafic Java RMI (JRMP) de pcaps_exemple/protocols/java_rmi/,
// entre deux JVM sur la boucle locale. Lance par tools/java_rmi_capture.sh.
//
//   server : registre sur 1099, objet Station exporte sur 50050, connecteur
//            JMX (RMI) sur 50051 avec un MBean qui emet des notifications.
//   client : list, lookup, appels normaux et exceptionnel, reutilisation
//            de connexion apres une pause (Ping), JMX avec notifications,
//            puis liberation des references (DGC clean).
//   raw    : deux connexions ecrites a la main, octet par octet : un appel
//            list() du registre en SingleOpProtocol, et un en-tete au
//            protocole inconnu, que le serveur refuse.

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import javax.management.Attribute;
import javax.management.AttributeChangeNotification;
import javax.management.MBeanServer;
import javax.management.MBeanServerConnection;
import javax.management.MBeanServerFactory;
import javax.management.NotificationBroadcasterSupport;
import javax.management.NotificationListener;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;

public class JrmpCapture {
    static final String HOST = "127.0.0.1";
    static final int REGISTRY_PORT = 1099;
    static final int STATION_PORT = 50050;
    static final int JMX_PORT = 50051;
    static final String JMX_URL =
            "service:jmx:rmi://" + HOST + ":" + JMX_PORT + "/jndi/rmi://" + HOST + ":" + REGISTRY_PORT + "/jmxrmi";

    public interface Station extends Remote {
        String hello(String name) throws RemoteException;

        int add(int a, int b) throws RemoteException;

        double[] samples(int count) throws RemoteException;

        void fail() throws RemoteException;
    }

    public static class StationImpl implements Station {
        public String hello(String name) {
            return "bonjour " + name;
        }

        public int add(int a, int b) {
            return a + b;
        }

        public double[] samples(int count) {
            double[] out = new double[count];
            for (int i = 0; i < count; i++) {
                out[i] = i * 0.5;
            }
            return out;
        }

        public void fail() throws RemoteException {
            throw new RemoteException("echec volontaire de la capture");
        }
    }

    public interface CounterMBean {
        int getValue();

        void setValue(int value);

        void reset();
    }

    public static class Counter extends NotificationBroadcasterSupport implements CounterMBean {
        private int value;
        private long sequence;

        public synchronized int getValue() {
            return value;
        }

        public synchronized void setValue(int next) {
            int previous = value;
            value = next;
            sendNotification(new AttributeChangeNotification(
                    this, ++sequence, 0L, "Value modifiee", "Value", "int", previous, next));
        }

        public void reset() {
            setValue(0);
        }
    }

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "server":
                server(Integer.parseInt(args[1]));
                break;
            case "client":
                client();
                break;
            case "raw":
                raw();
                break;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }

    static void server(int seconds) throws Exception {
        Registry registry = LocateRegistry.createRegistry(REGISTRY_PORT);
        StationImpl station = new StationImpl();
        registry.rebind("station", UnicastRemoteObject.exportObject(station, STATION_PORT));

        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        mbs.registerMBean(new Counter(), new ObjectName("capture:type=Counter"));
        JMXConnectorServer connector =
                JMXConnectorServerFactory.newJMXConnectorServer(new JMXServiceURL(JMX_URL), null, mbs);
        connector.start();
        System.out.println("pret");
        Thread.sleep(seconds * 1000L);
        connector.stop();
        System.exit(0);
    }

    static void client() throws Exception {
        Registry registry = LocateRegistry.getRegistry(HOST, REGISTRY_PORT);
        registry.list();
        Station station = (Station) registry.lookup("station");
        station.hello("capture");
        station.add(2, 3);
        station.samples(8);
        try {
            station.fail();
        } catch (RemoteException expected) {
            // retour exceptionnel attendu
        }
        // Connexion reutilisee apres une pause : le client la sonde par un Ping.
        Thread.sleep(400);
        station.add(40, 2);

        ObjectName counter = new ObjectName("capture:type=Counter");
        JMXConnector jmx = JMXConnectorFactory.connect(new JMXServiceURL(JMX_URL));
        MBeanServerConnection mbsc = jmx.getMBeanServerConnection();
        mbsc.getDefaultDomain();
        mbsc.getMBeanCount();
        NotificationListener listener = (notification, handback) -> { };
        mbsc.addNotificationListener(counter, listener, null, null);
        for (int i = 1; i <= 5; i++) {
            mbsc.setAttribute(counter, new Attribute("Value", i * 10));
            Thread.sleep(600);
            mbsc.getAttribute(counter, "Value");
        }
        mbsc.invoke(counter, "reset", null, null);
        // Bail DGC court cote serveur : le client renouvelle (dirty).
        Thread.sleep(2500);
        mbsc.removeNotificationListener(counter, listener);
        jmx.close();

        station = null;
        registry = null;
        System.gc();
        Thread.sleep(1500);
        System.gc();
        Thread.sleep(500);
        System.exit(0);
    }

    static void raw() throws Exception {
        // SingleOpProtocol : en-tete puis appel, sans ProtocolAck ; list() du
        // registre (ObjID 0, operation 1, hash de l'interface Registry).
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream header = new DataOutputStream(bytes);
        header.writeInt(0x4a524d49);
        header.writeShort(2);
        header.writeByte(0x4c);
        header.writeByte(0x50);
        header.flush();
        ObjectOutputStream call = new ObjectOutputStream(bytes);
        call.writeLong(0);
        call.writeInt(0);
        call.writeLong(0);
        call.writeShort(0);
        call.writeInt(1);
        call.writeLong(0x44154dc9d4e63bdfL);
        call.flush();
        exchange(bytes.toByteArray());

        // Protocole 0x4e : ni Stream, ni SingleOp, ni Multiplex.
        ByteArrayOutputStream refused = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(refused);
        out.writeInt(0x4a524d49);
        out.writeShort(2);
        out.writeByte(0x4e);
        out.flush();
        exchange(refused.toByteArray());
    }

    static void exchange(byte[] request) throws Exception {
        try (Socket socket = new Socket(HOST, REGISTRY_PORT)) {
            socket.getOutputStream().write(request);
            socket.getOutputStream().flush();
            InputStream in = new DataInputStream(socket.getInputStream());
            byte[] buffer = new byte[4096];
            while (in.read(buffer) >= 0) {
                // lire jusqu'a la fermeture par le serveur
            }
        }
    }
}
