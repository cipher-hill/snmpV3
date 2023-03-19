package org.example;

import java.io.IOException;
import java.util.ArrayList;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
public class TrapSenderVersion3 {
    public static final ArrayList<UsmUser> usmUserList = new
            ArrayList<UsmUser>();
    private final OctetString localEngineID = new OctetString(MPv3.createLocalEngineID()) ;
    public TrapSenderVersion3() {
        int engineBoots = 0;
        USM usm = new USM(SecurityProtocols.getInstance(),
                localEngineID,engineBoots);
        SecurityModels.getInstance().addSecurityModel(usm);
    }
    /**
     * The method will frame new V3 Trap and forward to Agent running on XP
     * machine
     */
    public void sendTrap_Version3() {
        TransportMapping<UdpAddress> transport;
        OctetString userName = new OctetString("privUser");
        usmUserList.add(new UsmUser(userName,
                AuthMD5.ID,
                new OctetString("authUser"),
                PrivDES.ID,
                new OctetString("privUser")));
        UsmUser[] usmUserArray = usmUserList.toArray(new UsmUser[0]);
        try {
            transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            snmp.getUSM().setUsers(usmUserArray);
            UserTarget<UdpAddress> target = new UserTarget<>();
            target.setAddress(new UdpAddress("127.0.0.1/162"));
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            target.setSecurityName(userName); //the user you want to send the trap
            target.setSecurityModel(SecurityModel.SECURITY_MODEL_USM);



//Preparing for PDU
            ScopedPDU pdu = new ScopedPDU();
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new
                    TimeTicks(1000)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID,
                    SnmpConstants.linkDown));// new OID(".1.3.6.1.2.1.1.8")));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new
                    IpAddress("10.120.7.108")));

//Sending the PDU
            pdu.setType(ScopedPDU.TRAP);
            pdu.setContextEngineID(localEngineID);
            snmp.send(pdu, target);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        TrapSenderVersion3 obj = new TrapSenderVersion3();
        obj.sendTrap_Version3();
    }
}