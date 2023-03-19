package org.example.check;


import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.TransportMapping;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class Checker {
    private static final String AGENT_ADDRESS = "udp:127.0.0.1/162";
    private static final String OID_TO_CHECK = "1.3.6.1.2.1.1.3.0";

    public static void main(String[] args) throws Exception {

        TransportMapping<?> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();
        USM usm = new USM(SecurityProtocols.getInstance()
                .addDefaultProtocols(), new OctetString(
                MPv3.createLocalEngineID()), 0);
        SecurityProtocols.getInstance().addPrivacyProtocol(new PrivDES());
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
        SecurityModels.getInstance().addSecurityModel(usm);


        snmp.getUSM().addUser(
                new OctetString("privUser"),
                new UsmUser(new OctetString("privUser"), AuthMD5.ID,
                        new OctetString("authUser"), PrivDES.ID,
                        new OctetString("privUser")));

        // Create Target
        UserTarget<Address> target = new UserTarget<>();
        target.setAddress(GenericAddress.parse(AGENT_ADDRESS));
        target.setRetries(2);
        target.setTimeout(1000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString("privUser"));


        // Create PDU for V3
        PDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID(OID_TO_CHECK)));
        pdu.setType(PDU.GET);


        ResponseEvent<Address> response = snmp.send(pdu, target);
        PDU responsePDU = response.getResponse();
        if (response.getResponse() != null) {
            Variable variable = responsePDU.get(0).getVariable();
            if (variable instanceof Null) {
                System.out.println("Value is null");
            } else if (variable instanceof Integer32) {
                int status = ((Integer32) variable).getValue();
                if (status == 1) {
                    System.out.println("Microservice is up");
                } else {
                    System.out.println("Microservice is down");
                }
            } else {
                System.out.println("Unexpected variable type: " + variable.getClass().getSimpleName());
            }
        } else {
            System.out.println("Failed to get status of microservice");
        }
        snmp.close();
    }
}