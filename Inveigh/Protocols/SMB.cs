using System;

namespace Inveigh
{
    class SMB
    {

        public static void SMBIncoming(byte[] payload, string destinationIP, string sourceIP, string snifferIP, string destinationPort, string sourcePort)
        {
            SMBConnection(payload, snifferIP, sourceIP, destinationIP, sourcePort, destinationPort);
            string session = GetSMB2Session(payload);

            if (String.IsNullOrEmpty(session))
            {
                session = GetSMB1Session(payload, destinationIP, destinationPort);
            }

            if (Program.smbSessionTable.ContainsKey(session))
            {
                NTLM.GetNTLMResponse(payload, sourceIP, sourcePort, "SMB", destinationPort, session);
            }

        }

        public static void SMBOutgoing(byte[] payload, string destinationIP, string snifferIP, string destinationPort, string sourcePort)
        {
            string challenge = NTLM.GetNTLMChallenge(payload);
            string session = GetSMB2Session(payload);

            if (String.IsNullOrEmpty(session))
            {
                session = GetSMB1Session(payload, destinationIP, destinationPort);
            }

            if (!String.IsNullOrEmpty(session) && !String.IsNullOrEmpty(challenge))
            {
                Program.smbSessionTable[session] = challenge;
                SMBChallenge(destinationIP, snifferIP, destinationPort, sourcePort, challenge);
            }
         
        }

        public static string GetSMB1Session(byte[] payload, string sourceIP, string sourcePort)
        {
            string hex = BitConverter.ToString(payload);
            hex = hex.Replace("-", String.Empty);
            int index = hex.IndexOf("FF534D42");
            string session = "";

            if (index >= 0)
            {
                session = sourceIP + ":" + sourcePort;
            }

            return session;
        }

        public static string GetSMB2Session(byte[] payload)
        {
            string hex = BitConverter.ToString(payload);
            hex = hex.Replace("-", String.Empty);
            int index = hex.IndexOf("FE534D42");
            string session = "";

            if (index >= 0)
            {
                session = hex.Substring((index + 80), 16);
            }

            return session;
        }

        public static void SMBChallenge(string destinationIP, string snifferIP, string destinationPort, string sourcePort, string challenge)
        {
            string session = destinationIP.ToString() + ":" + destinationPort;

            if (!String.IsNullOrEmpty(challenge))
            {

                if (!String.Equals(destinationIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}", DateTime.Now.ToString("s"), sourcePort, challenge, session));
                    }

                }
                else
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} from {3}", DateTime.Now.ToString("s"), sourcePort, challenge, session));
                    }

                }

            }

        }


        public static void SMBConnection(byte[] payload, string snifferIP, string sourceIP, string destinationIP, string sourcePort, string destinationPort)
        {
            string payloadHex = BitConverter.ToString(payload);
            payloadHex = payloadHex.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            string sessionOutgoing = destinationIP + ":" + destinationPort;
            int index = payloadHex.IndexOf("FF534D42");

            if (index > 0)
            {

                if (index > 0 && payloadHex.Substring((index + 8), 2) == "72" && !String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB1({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), destinationPort, session));
                    }

                }
                else if (index > 0 && payloadHex.Substring((index + 24), 4) == "0000" && String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB1({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                    }

                }

            }

            index = payloadHex.IndexOf("FE534D42");

            if (index > 0 && payloadHex.Substring((index + 24), 4) == "0000")
            {

                if (!String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB2+({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), destinationPort, session));
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

            index = payloadHex.IndexOf("2A864886F7120102020100");

            if (index > 0)
            {

                if (!String.Equals(sourceIP, snifferIP))
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[.] [{0}] SMB({1}) Kerberos authentication preferred from {2}", DateTime.Now.ToString("s"), destinationPort, session));
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
