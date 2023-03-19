package org.example;

import java.io.IOException;
import java.net.UnknownHostException;

import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;

import java.util.List;

import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;


/**
 * This is a class that implements the SNMP trap receiver functionality.
 */

public class SNMPTrapReceiver implements CommandResponder {
    private Snmp snmp = null;
    private int n = 0;
    private long start = -1;

    public SNMPTrapReceiver() {
    }

    public static void main(String[] args) {
        new SNMPTrapReceiver().run();
    }

    private void run() {
        try {
            init();
            snmp.addCommandResponder(this);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void init() throws UnknownHostException, IOException {
        ThreadPool threadPool = ThreadPool.create("Trap", 10);
        MultiThreadedMessageDispatcher dispatcher = new MultiThreadedMessageDispatcher(threadPool,
                new MessageDispatcherImpl());
        Address listenAddress = GenericAddress.parse(System.getProperty(
                "snmp4j.listenAddress", "udp:127.0.0.1/162"));
        TransportMapping<?> transport;
        if (listenAddress instanceof UdpAddress) {
            transport = new DefaultUdpTransportMapping(
                    (UdpAddress) listenAddress);
        } else {
            transport = new DefaultTcpTransportMapping(
                    (TcpAddress) listenAddress);
        }
        USM usm = new USM(
                SecurityProtocols.getInstance().addDefaultProtocols(),
                new OctetString(MPv3.createLocalEngineID()), 0);
        // SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
        usm.setEngineDiscoveryEnabled(true);

        snmp = new Snmp(dispatcher, transport);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.getUSM().addUser(
                new OctetString("MD5DES"),
                new UsmUser(new OctetString("MD5DES"), AuthMD5.ID,
                        new OctetString("authUser"), PrivDES.ID,
                        new OctetString("UserName")));

        snmp.listen();
    }

    public void processPdu(CommandResponderEvent event) {
        if (start < 0) {
            start = System.currentTimeMillis() - 1;
        }
        n++;
        if ((n % 100 == 1)) {
            System.out.println("Processed "
                    + (n / (double) (System.currentTimeMillis() - start))
                    * 1000 + "/s, total=" + n);
        }

        StringBuilder msg = new StringBuilder();
        msg.append(event.toString());
        List<? extends VariableBinding> varBinds = event.getPDU().getVariableBindings();
        if (varBinds != null && !varBinds.isEmpty()) {
            for (VariableBinding var : varBinds) {
                msg.append(var.toString()).append(";");
            }
        }
        System.out.println("Message Received: " + msg.toString());
    }
}