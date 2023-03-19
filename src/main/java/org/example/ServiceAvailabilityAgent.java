//package org.example;
//
//
//import org.snmp4j.*;
//import org.snmp4j.agent.*;
//import org.snmp4j.agent.mo.*;
//import org.snmp4j.mp.*;
//import org.snmp4j.smi.*;
//import org.snmp4j.smi.SMIConstants.SYNTAX_OID;
//import org.snmp4j.transport.*;
//import java.net.*;
//
//public class ServiceAvailabilityAgent implements CommandResponder {
//
//    private static final String SERVICE_OID = "1.3.6.1.4.1.1234.1";
//    private static final String SERVICE_ADDRESS = "192.168.0.67";
//    private static final int SERVICE_PORT = 8761;
//
//    private OctetString serviceName;
//    private TransportMapping transport;
//    private Snmp snmp;
//
//    public static void main(String[] args) throws Exception {
//        ServiceAvailabilityAgent agent = new ServiceAvailabilityAgent();
//        agent.start();
//    }
//
//    public void start() throws Exception {
//        serviceName = new OctetString(SERVICE_ADDRESS + ":" + SERVICE_PORT);
//        transport = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/0"));
//        snmp = new Snmp(transport);
//        snmp.addCommandResponder(this);
//
//        // Register managed object with custom OID
//        MOFactory moFactory = DefaultMOFactory.getInstance();
//        OID serviceOid = new OID(SERVICE_OID);
//        MOScalar<OctetString> serviceStatus = moFactory.createScalar(serviceOid,
//                MOAccessImpl.ACCESS_READ_ONLY, new OctetString());
//        registerManagedObject(serviceStatus);
//
//        transport.listen();
//        System.out.println("Service availability agent started.");
//    }
//
//    public void registerManagedObject(MOScalar<?> mo) {
//        DefaultMOTable table = new DefaultMOTable(serviceName, new MOTableIndex(
//                new MOTableSubIndex[] { new MOTableSubIndex(SMIConstants.SYNTAX_OID) },
//                false), new MOMutableTableModel());
//        table.getModel().addRow(new DefaultMOMutableRow2PC(new OID[] { mo.getOid() },
//                new Variable[] { mo.getValue() }));
//        snmp.registerManagedObject(mo, table);
//    }
//
//    @Override
//    public void processPdu(CommandResponderEvent event) {
//        PDU pdu = event.getPDU();
//        if (pdu.getType() == PDU.GET) {
//            OID oid = pdu.get(0).getOid();
//            if (SERVICE_OID.equals(oid.toString())) {
//                boolean isServiceAvailable = checkServiceAvailability();
//                pdu.setErrorIndex(0);
//                pdu.setErrorStatus(isServiceAvailable ? PDU.noError : PDU.genErr);
//                pdu.set(0, new VariableBinding(oid, new Integer32(isServiceAvailable ? 1 : 2)));
//                event.setPDU(pdu);
//            }
//        }
//    }
//
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
//    }
//}
