using System;
using System.Net;

namespace Inveigh
{
    class SMB
    {

        public static void SMBIncoming(byte[] payloadBytes, IPAddress destinationIPAddress, IPAddress sourceIPAddress, string snifferIP, int tcpDestinationPort, int tcpSourcePort)
        {
            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), destinationIPAddress.ToString(), Convert.ToString(tcpSourcePort), Convert.ToString(tcpDestinationPort));
            string session = GetSMB2Session(payloadBytes);

            if (String.IsNullOrEmpty(session))
            {
                session = GetSMB1Session(payloadBytes, destinationIPAddress.ToString(), tcpDestinationPort);
            }

            if (Program.smbSessionTable.ContainsKey(session))
            {
                NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", Convert.ToString(tcpDestinationPort), session);
            }

        }

        public static void SMBOutgoing(byte[] payloadBytes, IPAddress destinationIPAddress, string snifferIP, int tcpDestinationPort, int tcpSourcePort)
        {
            string challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
            string session = GetSMB2Session(payloadBytes);

            if (String.IsNullOrEmpty(session))
            {
                session = GetSMB1Session(payloadBytes, destinationIPAddress.ToString(), tcpDestinationPort);
            }

            Program.smbSessionTable[session] = challenge;

            SMBChallenge(destinationIPAddress.ToString(), snifferIP, tcpDestinationPort, tcpSourcePort, challenge);
        }

        public static string GetSMB1Session(byte[] field, string sourceIP, int sourcePort)
        {
            string payload = BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            int index = payload.IndexOf("FF534D42");
            string session = "";

            if (index > 0)
            {
                session = sourceIP + ":" + Convert.ToString(sourcePort);
            }

            return session;
        }

        public static string GetSMB2Session(byte[] field)
        {
            string payload = BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            int index = payload.IndexOf("FE534D42");
            string session = "";

            if (index > 0)
            {
                session = payload.Substring((index + 80), 16);
            }

            return session;
        }

        public static void SMBChallenge(string destinationIP, string snifferIP, int tcpDestinationPort, int tcpSourcePort, string challenge)
        {
            string session = destinationIP.ToString() + ":" + Convert.ToString(tcpDestinationPort);

            if (!String.IsNullOrEmpty(challenge))
            {

                if (!String.Equals(destinationIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                    }

                }
                else
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} from {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                    }

                }

            }

        }


        public static void SMBConnection(byte[] field, string snifferIP, string sourceIP, string destinationIP, string sourcePort, string smbPort)
        {
            string payload = BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            string sessionOutgoing = destinationIP + ":" + smbPort;
            int index = payload.IndexOf("FF534D42");

            if (index > 0)
            {

                if (index > 0 && payload.Substring((index + 8), 2) == "72" && !String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB1({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), smbPort, session));
                    }

                }
                else if (index > 0 && payload.Substring((index + 24), 4) == "0000" && String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB1({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                    }

                }

            }

            index = payload.IndexOf("FE534D42");

            if (index > 0 && payload.Substring((index + 24), 4) == "0000")
            {

                if (!String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB2+({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), smbPort, session));
                    }

                }
                else
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB2+({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                    }

                }

            }

            index = payload.IndexOf("2A864886F7120102020100");

            if (index > 0)
            {

                if (!String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB({1}) Kerberos authentication preferred from {2}", DateTime.Now.ToString("s"), smbPort, session));
                    }

                }
                else
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB({1}) Kerberos authentication preferred to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                    }

                }

            }

        }

    }

}
