package org.example.snmp;

import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.TSM;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.snmp4j.*;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.*;
import org.snmp4j.util.*;


public class MultiThreadedTrapReceiver implements CommandResponder {

    private final Address address = GenericAddress.parse("0.0.0.0/162");
    private final OID authProtocol = AuthMD5.ID;
    private final OID privProtocol = PrivDES.ID;
    private final OctetString securityName = new OctetString("privUser");
    private final OctetString privPassphrase = new OctetString("privUser");
    private final OctetString authPassphrase = new OctetString("authUser");
    private static final OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());


    public MultiThreadedTrapReceiver() {
        try {
            listen();
        } catch (IOException ex) {
            Logger.getLogger(MultiThreadedTrapReceiver.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public synchronized void listen() throws IOException {
        AbstractTransportMapping transport;
        if (address instanceof TcpAddress) {
            transport = new DefaultTcpTransportMapping((TcpAddress) address);
        } else {
            transport = new DefaultUdpTransportMapping((UdpAddress) address);
        }
        int numDispatcherThreads = 10;
        ThreadPool threadPool =
                ThreadPool.create("DispatcherPool", numDispatcherThreads);
        MessageDispatcher mtDispatcher =
                new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

        // add message processing models
        mtDispatcher.addMessageProcessingModel(new MPv1());
        mtDispatcher.addMessageProcessingModel(new MPv2c());
        mtDispatcher.addMessageProcessingModel(new MPv3());

        SecurityModels.getInstance().addSecurityModel(new TSM(localEngineId, false));

        // add all security protocols
        SecurityProtocols securityProtocols = SecurityProtocols.getInstance();
        securityProtocols.addDefaultProtocols();
        securityProtocols.addAuthenticationProtocol(new AuthMD5());
        securityProtocols.addAuthenticationProtocol(new AuthSHA());
        securityProtocols.addPrivacyProtocol(new PrivDES());
        securityProtocols.addPrivacyProtocol(new Priv3DES());
        securityProtocols.addPrivacyProtocol(new PrivAES128());
        securityProtocols.addPrivacyProtocol(new PrivAES192());
        securityProtocols.addPrivacyProtocol(new PrivAES256());

        Snmp snmp = new Snmp(mtDispatcher, transport);
        USM usm = new USM(SecurityProtocols.getInstance(),  localEngineId, 0);
        usm.setEngineDiscoveryEnabled(true);
        SecurityModels.getInstance().addSecurityModel(usm);
        // Add the configured user to the USM
        addUsmUser(snmp);

        snmp.addCommandResponder(this);

        transport.listen();

        try {
            this.wait();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private void addUsmUser(Snmp snmp) {
        snmp.getUSM().addUser(securityName, new UsmUser(securityName,
                authProtocol,
                authPassphrase,
                privProtocol,
                privPassphrase));
    }

    @Override
    public void processPdu(CommandResponderEvent respEvnt) {
        System.out.println(respEvnt.getPDU());
        InetAddress pduAgentAddress = null;
        //System.out.println(respEvnt.getPDU() + " recieved;");
        //this.setPdu(respEvnt.getPDU());
        OctetString community = new OctetString(respEvnt.getSecurityName());
        System.out.println("community: " + community.toString());

        Address address = respEvnt.getPeerAddress();
        String hostName = address.toString().split("/")[0];
        int nPort = Integer.parseInt(address.toString().split("/")[1]);

        //handle the SNMP v1
        if (respEvnt.getPDU().getType() == PDU.TRAP) {
            try {
                pduAgentAddress = InetAddress.getByName(hostName);
            } catch (UnknownHostException ex) {
                Logger.getLogger(MultiThreadedTrapReceiver.class.getName()).log(Level.SEVERE, null, ex);
            }
            assert pduAgentAddress != null;
            System.out.println("hostname: " + pduAgentAddress.getHostAddress() + "; port: " + nPort);
        } else {
            try {
                pduAgentAddress = InetAddress.getByName(hostName);
            } catch (UnknownHostException ex) {
                Logger.getLogger(MultiThreadedTrapReceiver.class.getName()).log(Level.SEVERE, null, ex);
            }
            assert pduAgentAddress != null;
            System.out.println("hostname: " + pduAgentAddress.getHostAddress() + "; port: " + nPort);
        }
    }

    public static void main(String[] args) {
        MultiThreadedTrapReceiver trap = new MultiThreadedTrapReceiver();
    }
}
