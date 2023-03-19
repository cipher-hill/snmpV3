package org.example;

import java.io.IOException;
import java.util.List;

import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.*;


public class SnmpUtilSendTrapV3 {

    private Snmp snmp = null;
    private Address targetAddress = null;
    public void initComm() throws IOException {
        targetAddress = GenericAddress.parse("127.0.0.1/162");
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        snmp.listen();
    }


    public void sendPDU() throws IOException {
        UserTarget<Address> target = new UserTarget<>();
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        // snmp version
        target.setVersion(SnmpConstants.version3);


        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString("privUser"));

        USM usm = new USM(SecurityProtocols.getInstance(),
               new OctetString(MPv3.createLocalEngineID()), 0);
        usm.setEngineDiscoveryEnabled(true);
        SecurityModels.getInstance().addSecurityModel(usm);

        UsmUser user = new UsmUser(new OctetString("privUser"),
                AuthMD5.ID,
                new OctetString("authUser"),
                PrivDES.ID,
                new OctetString("privUser"));
        snmp.getUSM().addUser(new OctetString("privUser"), user);

        // create PDU
        ScopedPDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.3.0"),
                new OctetString("SnmpTrapv3")));
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.5.0"),
                new OctetString("JavaEE")));
        pdu.setType(PDU.TRAP);

        // send PDU to Agent and receive Response
        ResponseEvent<Address> respEvnt = snmp.send(pdu, target);

        // analyze Response
        if (respEvnt != null && respEvnt.getResponse() != null) {
            List<? extends VariableBinding> recVBs =  respEvnt.getResponse().getVariableBindings();
            for (VariableBinding recVB : recVBs) {
                System.out.println(recVB.getOid() + " : " + recVB.getVariable());
            }
        }
        snmp.close();
    }

    public static void main(String[] args) {
        try {
            SnmpUtilSendTrapV3 util = new SnmpUtilSendTrapV3();
            util.initComm();
            util.sendPDU();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
