package org.example;
import java.io.IOException;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SNMPManager {

    Snmp snmp = null;
    String Agent = "udp:127.0.0.1/162";
    String Oid=".1.3.6.1.4.1.53427.1.4.3";

    public static void main(String[] args) throws IOException {

        SNMPManager client = new SNMPManager();
        client.start();
        String ODIValue = client.getAsString(new OID(client.Oid));
        System.out.println("OID is "+ client.Oid);
        System.out.println("ODIValue is "+ODIValue);
        System.out.println("---------------------------------------------");
    }

    private void start() throws IOException {
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        transport.listen();
    }


    public String getAsString(OID oid) throws IOException {
        ResponseEvent<Address> res = getEvent(new OID[] { oid });
        if(res!=null)
            return res.getResponse().get(0).getVariable().toString();
        return null;
    }

    public ResponseEvent<Address> getEvent(OID[] oids) throws IOException
    {
        PDU pdu = new PDU();
        for (OID oid : oids) {
            pdu.add(new VariableBinding(oid));
        }
        pdu.setType(PDU.GET);
        ResponseEvent<Address> event = snmp.send(pdu, getTarget(), null);
        if(event != null) {
            return event;
        }
        throw new RuntimeException("GET timed out");
    }

    private Target<Address> getTarget() {
        Address targetAddress = GenericAddress.parse(Agent);
        CommunityTarget<Address> target = new CommunityTarget<>();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);
        return target;
    }

}