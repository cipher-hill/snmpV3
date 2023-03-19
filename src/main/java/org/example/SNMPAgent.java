package org.example;

import org.snmp4j.*;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.*;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.*;
import org.snmp4j.tools.console.SnmpCommand;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;

public class SNMPAgent implements CommandResponder
{


    public static void main(String[] args)
    {
        SNMPAgent snmp4jTrapReceiver = new SNMPAgent();
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

        // add all security protocols
        SecurityProtocols.getInstance().addDefaultProtocols();
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        //Create Target
        CommunityTarget<Address> target = new CommunityTarget<>();
        target.setCommunity( new OctetString("public"));

        Snmp snmp = new Snmp(mtDispatcher, transport);
        snmp.addCommandResponder(this);

        transport.listen();
        System.out.println("SNMP Agent Listening on " + address);

        try
        {
            this.wait();
        }
        catch (InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }
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

                // forming response for requested OID request
                if(pdu.get(0).getOid().equals(new OID(".1.3.6.1.4.1.53427.1.4.2")))
                {
                    System.out.println("requested OID is  "+pdu.get(0).getOid());
                    pdu.set(0, new VariableBinding(new OID(pdu.get(0).getOid()), new Integer32(100)));
                    //pdu.add(new VariableBinding(new OID(pdu.get(0).getOid()), new Integer32(100)));
                }

                else if(pdu.get(0).getOid().equals(new OID(".1.3.6.1.4.1.53427.1.4.3")))

                {
                    System.out.println("requested OID is  "+pdu.get(0).getOid());
                    pdu.set(0, new VariableBinding(new OID(pdu.get(0).getOid()), new Integer32(200)));
                    //pdu.add(new VariableBinding(new OID(pdu.get(0).getOid()), new Integer32(200)));
                }
                else if(pdu.get(0).getOid().equals(new OID(".1.3.6.1.4.1.53427.1.4.5")))
                {
                    System.out.println("requested OID is  "+pdu.get(0).getOid());
                    pdu.set(0, new VariableBinding(new OID(pdu.get(0).getOid()), new Integer32(300)));
                }
                else
                {
                    pdu.clear();
                }


                pdu.setType(PDU.RESPONSE);

                StatusInformation statusInformation = new StatusInformation();
                StateReference ref = cmdRespEvent.getStateReference();
                try
                {
                    System.out.println("response sent please check your SNMP manager");
                    System.out.println(cmdRespEvent.getPDU());
                    cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
                            cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
                            pdu, cmdRespEvent.getMaxSizeResponsePDU(), ref, statusInformation);
                }
                catch (MessageException ex)
                {
                    System.err.println("Error while sending response: " + ex.getMessage());
                    LogFactory.getLogger(SnmpCommand.class).error(ex);
                }
            }
        }
    }
}