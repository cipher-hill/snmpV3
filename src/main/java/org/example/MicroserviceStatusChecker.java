package org.example;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.Arrays;
import java.util.List;

public class MicroserviceStatusChecker {
    private static final String AGENT_ADDRESS = "udp:127.0.0.1/162";
    private static final String COMMUNITY_STRING = "public";
    private static final List<String> OIDS_TO_CHECK = Arrays.asList(
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.1.4.0",
            "1.3.6.1.2.1.1.5.0"
    );

    public static void main(String[] args) throws Exception {
        TransportMapping<?> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        CommunityTarget<Address> target = new CommunityTarget<>();
        target.setCommunity(new OctetString(COMMUNITY_STRING));
        target.setAddress(GenericAddress.parse(AGENT_ADDRESS));
        target.setRetries(1);
        target.setTimeout(1000);
        target.setVersion(SnmpConstants.version2c);

        for (String oidToCheck : OIDS_TO_CHECK) {
            PDU pdu = new PDU();
            pdu.setType(PDU.GET);
            pdu.add(new VariableBinding(new OID(oidToCheck)));

            ResponseEvent<Address> response = snmp.send(pdu, target);
            if (response != null && response.getResponse() != null) {
                Variable variable = response.getResponse().get(0).getVariable();
                if (variable instanceof Null) {
                    System.out.println(oidToCheck + " value is null");
                } else if (variable instanceof Integer32) {
                    int status = ((Integer32) variable).getValue();
                    if (status == 1) {
                        System.out.println(oidToCheck + " is up");
                    } else {
                        System.out.println(oidToCheck + " is down");
                    }
                } else {
                    System.out.println(oidToCheck + " unexpected variable type: " + variable.getClass().getSimpleName());
                }
            } else {
                System.out.println("Failed to get status of " + oidToCheck);
            }
        }
        snmp.close();
    }
}













//
//import org.snmp4j.CommunityTarget;
//import org.snmp4j.PDU;
//import org.snmp4j.Snmp;
//import org.snmp4j.TransportMapping;
//import org.snmp4j.event.ResponseEvent;
//import org.snmp4j.mp.SnmpConstants;
//import org.snmp4j.smi.Address;
//import org.snmp4j.smi.GenericAddress;
//import org.snmp4j.smi.OID;
//import org.snmp4j.smi.OctetString;
//import org.snmp4j.smi.VariableBinding;
//import org.snmp4j.transport.DefaultUdpTransportMapping;
//
//public class MicroserviceStatusChecker {
//    public static void main(String[] args) throws Exception {
//        // Define the OID for sysUpTime
//        OID sysUpTimeOID = new OID("1.3.6.1.2.1.1.3.0");
//
//        // Create an SNMP manager
//        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
//        Snmp snmp = new Snmp(transport);
//
//        // Create an SNMP target
//        Address targetAddress = GenericAddress.parse("udp:localhost/161");
//        CommunityTarget<Address> target = new CommunityTarget<>();
//        target.setCommunity(new OctetString("public"));
//        target.setAddress(targetAddress);
//        target.setVersion(SnmpConstants.version2c);
//
//        // Create an SNMP request
//        PDU pdu = new PDU();
//        pdu.add(new VariableBinding(sysUpTimeOID));
//        pdu.setType(PDU.GET);
//
//        // Send the request
//        ResponseEvent<Address> response = snmp.send(pdu, target);
//
//        // Process the response
//        if (response.getResponse() == null) {
//            System.out.println("Microservice is down.");
//        } else {
//            System.out.println("Microservice is up.");
//            VariableBinding vb = response.getResponse().get(0);
//            long sysUpTime = vb.getVariable().toLong();
//            System.out.println("System uptime: " + sysUpTime);
//        }
//
//        // Close the SNMP manager
//        snmp.close();
//    }
//}
//
