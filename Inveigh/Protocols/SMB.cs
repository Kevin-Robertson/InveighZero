using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Quiddity;
using Quiddity.SMB;
using Quiddity.SMB2;
using Quiddity.NetBIOS;

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

        public static void SMBListener(string method, string ipVersion, string tcpIP, string tcpPort)
        {
            Guid guid = Guid.NewGuid();
            TcpListener tcpListener = null;
            TcpClient tcpClient = new TcpClient();
            IAsyncResult tcpAsync;
            IPAddress listenerIPAddress = IPAddress.Any;

            if (String.Equals(ipVersion, "IPv4") && !String.Equals(tcpIP, "0.0.0.0"))
            {
                listenerIPAddress = IPAddress.Parse(tcpIP);
            }
            else if (String.Equals(ipVersion, "IPv6"))
            {
                listenerIPAddress = IPAddress.IPv6Any;
            }

            int tcpPortNumber = Int32.Parse(tcpPort);
            tcpListener = new TcpListener(listenerIPAddress, tcpPortNumber);
            tcpListener.Server.ExclusiveAddressUse = false;
            tcpListener.ExclusiveAddressUse = false;
            tcpListener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            try
            {
                tcpListener.Start();
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[!] Error starting unprivileged {1} listener, check IP and port usage.", DateTime.Now.ToString("s"), method));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {
                tcpAsync = tcpListener.BeginAcceptTcpClient(null, null);

                do
                {
                    Thread.Sleep(10);

                    if (Program.exitInveigh)
                    {
                        break;
                    }

                }
                while (!tcpAsync.IsCompleted);

                tcpClient = tcpListener.EndAcceptTcpClient(tcpAsync);
                object[] httpParams = { guid, tcpClient };
                ThreadPool.QueueUserWorkItem(new WaitCallback(GetSMBClient), httpParams);
            }

        }

        public static void GetSMBClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            Guid serverGuid = (Guid)parameterArray[0];
            TcpClient tcpClient = (TcpClient)parameterArray[1];
            NetworkStream tcpStream = tcpClient.GetStream();
            bool isSMB2;

            string sourceIP = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Address.ToString();
            string sourcePort = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Port.ToString();
            NetBIOSSessionService netbiosSessionServiceReceive = new NetBIOSSessionService();

            while (tcpClient.Connected)
            {
                byte[] requestData = new byte[4096];

                do
                {
                    Thread.Sleep(100);
                }
                while (!tcpStream.DataAvailable && tcpClient.Connected);

                while (tcpStream.DataAvailable)
                {
                    tcpStream.Read(requestData, 0, requestData.Length);
                }
                
                netbiosSessionServiceReceive = netbiosSessionServiceReceive.Read(requestData);                         

                if (netbiosSessionServiceReceive.Type == 0)
                {
                    SMBHelper smbHelper = new SMBHelper();
                    SMBHeader smbHeaderReceive = new SMBHeader();
                    SMB2Header smb2HeaderReceive = new SMB2Header();
                    smbHelper.ReadBytes(requestData, 4);

                    if (smbHelper.Protocol[0] == 0xfe)
                    {
                        isSMB2 = true;
                        smb2HeaderReceive.ReadBytes(requestData, 4);
                    }
                    else
                    {
                        isSMB2 = false;
                        smbHeaderReceive.ReadBytes(requestData, 4);
                    }

                    if (!isSMB2 && smbHeaderReceive.Command[0] == 0x72 || (isSMB2 && smb2HeaderReceive.Command == 0))
                    {
                        SMB2Packet smb2Packet = new SMB2Packet();
                        SMB2NegotiateResponse command = new SMB2NegotiateResponse();

                        if (!isSMB2)
                        {
                            command.DialectRivision = new byte[2] { 0xff, 0x02 };
                            command.Capabilities = new byte[4] { 0x07, 0x00, 0x00, 0x00 };
                        }
                        else if (isSMB2)
                        {
                            smb2Packet.Header.MessageId = smb2HeaderReceive.MessageId;
                            command.DialectRivision = new byte[2] { 0x11, 0x03 };
                            command.NegotiateContextCount = 3;
                            command.Capabilities = new byte[4] { 0x2f, 0x00, 0x00, 0x00 };
                            command.NegotiateContextOffset = 448;
                            command.NegotiateContextList = new SMB2NegotiateContext().GetBytes(new string[] { "1","2","3" });
                            smb2Packet.Header.Reserved2 = smb2HeaderReceive.Reserved2;
                        }

                        command.ServerGUID = serverGuid.ToByteArray();
                        smb2Packet.Payload = command;
                        smb2Packet.Write(smb2Packet, tcpStream);
                    }
                    else if (isSMB2 && smb2HeaderReceive.Command > 0)
                    {

                        switch (smb2HeaderReceive.Command)
                        {

                            case 1:
                            {
                                SMB2Packet smb2Packet = new SMB2Packet();
                                SMB2SessionSetupResponse sessionSetupResponse = new SMB2SessionSetupResponse();
                                smb2Packet.Header.Status = new byte[4] { 0x16, 0x00, 0x00, 0xc0 };
                                smb2Packet.Header.CreditCharge = 1;
                                smb2Packet.Header.Reserved2 = smb2HeaderReceive.Reserved2;
                                smb2Packet.Header.Command = 1;
                                smb2Packet.Header.Flags = new byte[4] { 0x11, 0x00, 0x00, 0x00 };
                                smb2Packet.Header.MessageId = smb2HeaderReceive.MessageId;
                                smb2Packet.Header.SessionId = BitConverter.GetBytes(Program.smb2Session);
                                Program.smb2Session++;
                                sessionSetupResponse.Pack(out byte[] challengeData);
                                smb2Packet.Payload = sessionSetupResponse;
                                smb2Packet.Write(smb2Packet, tcpStream);
                                string challenge = BitConverter.ToString(challengeData).Replace("-","");

                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}:{4}", DateTime.Now.ToString("s"), 445, challenge, sourceIP, sourcePort));
                                }

                            }
                            break;

                        }

                    }

                }
                else
                {
                    //tcpClient.Close();
                }

            }

        }

    }

}
