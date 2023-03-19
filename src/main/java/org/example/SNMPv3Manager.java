package org.example;

import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SNMPv3Manager {

    public static void main(String[] args) throws Exception {
        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);

        UsmUser user = new UsmUser(new OctetString("SHADES"),
                AuthSHA.ID,
                new OctetString("SHADESUserAuthPassword"),
                PrivAES256.ID,
                new OctetString("SHADESUserPrivPassword"));
        snmp.getUSM().addUser(new OctetString("SHADES"), user);
        SecurityModels.getInstance().addSecurityModel(new TSM(localEngineId, false));

        UserTarget target = new UserTarget();
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString("MD5DES"));

        target.setAddress(GenericAddress.parse(String.format("udp:%s/%s", "127.0.0.1", "162")));
        target.setVersion(SnmpConstants.version3);
        target.setRetries(2);
        target.setTimeout(60000);

        transport.listen();

        PDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID(".1.3.6.1.4.1.53427.1.4.3"), new OctetString("Hello world!")));
        pdu.setType(PDU.TRAP);
        ResponseEvent event = snmp.send(pdu, target);
        if (event != null) {
            pdu = event.getResponse();
            if (pdu.getErrorStatus() == PDU.noError) {
                System.out.println("SNMPv3 SET Successful!");
            } else {
                System.out.println("SNMPv3 SET Unsuccessful.");
            }
        } else {
            System.out.println("SNMP send unsuccessful.");
        }
    }
}


















//
//import org.snmp4j.*;
//import org.snmp4j.fluent.SnmpBuilder;
//import org.snmp4j.fluent.SnmpCompletableFuture;
//import org.snmp4j.fluent.TargetBuilder;
//import org.snmp4j.smi.*;
//
//import java.io.IOException;
//import java.util.List;
//import java.util.concurrent.ExecutionException;
//
//
//public class SNMPv3Manager {
//    public void nextFluent(String address, String contextName, String securityName,
//                           String authPassphrase, String privPassphrase, String... oids) throws IOException {
//        SnmpBuilder snmpBuilder = new SnmpBuilder();
//        Snmp snmp = snmpBuilder.udp().v3().usm().threads(2).build();
//        snmp.listen();
//        Address targetAddress = GenericAddress.parse(address);
//        if (targetAddress != null) {
//            byte[] targetEngineID = snmp.discoverAuthoritativeEngineID(targetAddress, 9000);
//            if (targetEngineID != null) {
//                TargetBuilder<?> targetBuilder = snmpBuilder.target(targetAddress);
//                Target<?> userTarget = targetBuilder
//                        .user(securityName, targetEngineID)
//                        .auth(TargetBuilder.AuthProtocol.hmac192sha256).authPassphrase(authPassphrase)
//                        .priv(TargetBuilder.PrivProtocol.aes128).privPassphrase(privPassphrase)
//                        .done()
//                        .timeout(500).retries(1)
//                        .build();
//
//                ScopedPDU pdu = (ScopedPDU) targetBuilder.pdu().type(ScopedPDU.GETNEXT).oids(oids).contextName(contextName).build();
//                SnmpCompletableFuture snmpRequestFuture = SnmpCompletableFuture.send(snmp, userTarget, pdu);
//                try {
//                    List<VariableBinding> vbs = snmpRequestFuture.get().getAll();
//
//                    System.out.println("Received: " + snmpRequestFuture.getResponseEvent().getResponse());
//                    System.out.println("Payload:  " + vbs);
//                } catch (ExecutionException | InterruptedException ex) {
//                    if (ex.getCause() != null) {
//                        System.err.println(ex.getCause().getMessage());
//                    } else {
//                        System.err.println("Request failed: " + ex.getMessage());
//                    }
//                }
//            } else {
//                System.err.println("Timeout on engine ID discovery for " + targetAddress + ", GETNEXT not sent.");
//            }
//            snmp.close();
//        }
//        else {
//            System.err.println("Invalid target address: "+address);
//        }
//    }
//
//    public static void main(String[] args) {
//        if (args.length < 5) {
//            System.out.println("Usage: UsmGetNext <address> <secName> <authPassphrase> <privPassphrase> <oid>...");
//            System.out.println("where <address> is of the form 'udp:<hostname>/<port>'");
//        }
//        String targetAddress = args[0];
//        String context = "";
//        String securityName = args[1];
//        String authPasssphrase = args[2].length() == 0 ? null : args[2];
//        String privPasssphrase = args[3].length() == 0 ? null : args[3];
//        String[] oids = new String[args.length - 4];
//        System.arraycopy(args, 4, oids, 0, args.length - 4);
//        SNMPv3Manager usmGetNext = new SNMPv3Manager();
//        try {
//            usmGetNext.nextFluent(targetAddress, context, securityName, authPasssphrase, privPasssphrase, oids);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//}
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//




