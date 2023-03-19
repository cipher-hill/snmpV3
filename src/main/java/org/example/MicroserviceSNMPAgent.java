package org.example;

import org.apache.commons.net.telnet.TelnetClient;
import org.snmp4j.*;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;
import org.springframework.core.env.Environment;
import org.springframework.util.ObjectUtils;
import lombok.extern.apachecommons.CommonsLog;
import java.io.IOException;
import java.util.Properties;


@CommonsLog
public class MicroserviceSNMPAgent implements CommandResponder {

    private final OID authProtocol = AuthMD5.ID;
    private final OID privProtocol = PrivDES.ID;
    private final OctetString securityName = new OctetString("privUser");
    private final OctetString privPassphrase = new OctetString("privUser");
    private final OctetString authPassphrase = new OctetString("authUser");
    private static final OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());



    public static void main(String[] args) throws Exception {
        MicroserviceSNMPAgent snmp4jTrapReceiver = new MicroserviceSNMPAgent ();
        try
        {
            snmp4jTrapReceiver.listen(new UdpAddress("127.0.0.1/162"));
        }
        catch (IOException e)
        {
            System.err.println("Error in Listening for Trap");
            System.err.println("Exception Message = " + e.getMessage());
        }
    }




    public synchronized void listen(TransportIpAddress address) throws IOException
    {
        AbstractTransportMapping transport;
        if (address instanceof TcpAddress)
        {
            transport = new DefaultTcpTransportMapping((TcpAddress) address);
        }
        else
        {
            transport = new DefaultUdpTransportMapping((UdpAddress) address);
        }

        ThreadPool threadPool = ThreadPool.create("DispatcherPool", 10);
        MessageDispatcher mtDispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

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

        //Create Target
//        CommunityTarget<Address> target = new CommunityTarget<>();
//        target.setCommunity( new OctetString("public"));

        Snmp snmp = new Snmp(mtDispatcher, transport);
        USM usm = new USM(SecurityProtocols.getInstance(),  localEngineId, 0);
        usm.setEngineDiscoveryEnabled(true);
        SecurityModels.getInstance().addSecurityModel(usm);

        // Add the configured user to the USM
        addUsmUser(snmp);

        snmp.addCommandResponder(this);

        transport.listen();
        System.out.println("My Microservice is Listening on " + address);

        try
        {
            this.wait();
        }
        catch (InterruptedException ex)
        {
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
    /**
     * This method will be called whenever a pdu is received on the given port specified in the listen() method
     */
    public synchronized void processPdu(CommandResponderEvent cmdRespEvent)
    {
        PDU pdu = cmdRespEvent.getPDU();
        if (pdu != null)
        {
            int pduType = pdu.getType();
            if ((pduType != PDU.TRAP) && (pduType != PDU.V1TRAP) && (pduType != PDU.REPORT)
                    && (pduType != PDU.RESPONSE))
            {
                pdu.setErrorIndex(0);
                pdu.setErrorStatus(0);
                // Check if the received OID is one of the configured OIDs
                String oid = pdu.get(0).getOid().toString();
                String url = getConfiguredUrlForOid(oid);
                if (url != null) {
                    boolean isServiceAvailable = checkFluxByHostAndPort(url, 1000);
                    pdu.set(0, new VariableBinding(new OID(oid), new Integer32(isServiceAvailable ? 1 : 0)));
                    pdu.setType(PDU.RESPONSE);
                    try {
                        cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
                                cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
                                pdu, cmdRespEvent.getMaxSizeResponsePDU(), cmdRespEvent.getStateReference(),
                                new StatusInformation());
                    } catch (MessageException e) {
                        System.err.println("Error sending response: " + e.getMessage());
                    }
                } else {
                    pdu.clear();
                }
            }
        }
    }

    private String getConfiguredUrlForOid(String oid) {
        // Load the configured OIDs and their corresponding URLs from a properties file or a database
        Properties props = loadConfiguredOidsAndUrls();
        return props.getProperty(oid);
    }


//    public Properties loadConfiguredOidsAndUrls() {
//        Properties props = new Properties();
//
//        String discoveryUrl = env.getProperty("service.url.discovery");
//        String discoveryOid = env.getProperty("service.url.discovery.oid");
//        String configUrl = env.getProperty("service.url.config");
//        String configOid = env.getProperty("service.url.config.oid");
//
//        props.setProperty(discoveryOid, discoveryUrl);
//        props.setProperty(configOid, configUrl);
//        // Add more properties as needed
//
//        return props;
//    }

    private Properties loadConfiguredOidsAndUrls() {
        // Load the configured OIDs and their corresponding URLs from a properties file or a database
        Properties props = new Properties();
        props.setProperty("1.3.6.1.2.1.1.3.0", "192.168.0.67:8761");
        props.setProperty("1.3.6.1.2.1.1.4.0", "192.168.0.67:8888");
        props.setProperty("1.3.6.1.2.1.1.5.0", "192.168.0.67:8081");
        // Add more properties as needed
        return props;
    }


    public boolean checkFluxByHostAndPort(String url, int timeout){
        if (!ObjectUtils.isEmpty(url)) {
            String host = url.split(":")[0];
            int port = Integer.parseInt(url.split(":")[1]);
            try {
                TelnetClient telnet = new TelnetClient();
                telnet.setConnectTimeout(timeout);
                telnet.connect(host, port);
                telnet.disconnect();
                log.info(url + " connected --- OK");
                return true;
            } catch (Exception e) {
                log.warn(url + " not connected --- KO");
            }
        }
        return false;
    }
}

//    PDU pdu = cmdRespEvent.getPDU();
//        if (pdu != null)
//                {
//                int pduType = pdu.getType();
//                if ((pduType != PDU.TRAP) && (pduType != PDU.V1TRAP) && (pduType != PDU.REPORT)
//                && (pduType != PDU.RESPONSE))
//                {
//                pdu.setErrorIndex(0);
//                pdu.setErrorStatus(0);
//                if (pdu.get(0).getOid().equals(new OID("1.3.6.1.2.1.1.3.0"))) { // OID for service status check
//                boolean isServiceAvailable = checkFluxByHostAndPort("192.168.0.67:8761",1000);
//                pdu.set(0, new VariableBinding(new OID(pdu.get(0).getOid()), new Integer32(isServiceAvailable ? 1 : 0)));
//                pdu.setType(PDU.RESPONSE);
//                try {
//                cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
//                cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
//                pdu, cmdRespEvent.getMaxSizeResponsePDU(), cmdRespEvent.getStateReference(),
//                new StatusInformation());
//                } catch (MessageException e) {
//                System.err.println("Error sending response: " + e.getMessage());
//                }
//                }
//                else {
//                pdu.clear();
//                }
//                }
//                }

//    private boolean checkServiceAvailability() {
//        try {
//            URL url = new URL("http://192.168.0.67:8761");
//            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
//            connection.setRequestMethod("HEAD");
//            int responseCode = connection.getResponseCode();
//            return responseCode >= 200 && responseCode < 400;
//        } catch (Exception ex) {
//            return false;
//        }
//