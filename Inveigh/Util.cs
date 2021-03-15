using System;
using System.Linq;
using System.Text;
using System.Net;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class Util
    {

        public static string HexStringToString(string hex)
        {
            string[] characters = hex.Split('-');
            string converted = "";

            foreach (string character in characters)
            {
                converted += new String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
            }

            return converted;
        }

        public static uint UInt16DataLength(int start, byte[] data)
        {
            byte[] payloadExtract = new byte[2];

            if (data.Length > start + 2)
            {
                Buffer.BlockCopy(data, start, payloadExtract, 0, 2);
            }

            return BitConverter.ToUInt16(payloadExtract, 0);
        }

        public static uint UInt32DataLength(int start, byte[] data)
        {
            byte[] dataExtract = new byte[4];
            Buffer.BlockCopy(data, start, dataExtract, 0, 4);
            return BitConverter.ToUInt32(dataExtract, 0);
        }

        public static ushort DataToUInt16(byte[] data)
        {
            Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static uint DataToUInt32(byte[] data)
        {
            Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static string DataToString(int start, int length, byte[] data)
        {
            string converted = "";

            if (length > 0)
            {
                byte[] dataExtract = new byte[length - 1];
                Buffer.BlockCopy(data, start, dataExtract, 0, dataExtract.Length);
                string hex = BitConverter.ToString(dataExtract);
                hex = hex.Replace("-00", String.Empty);
                string[] payloadArray = hex.Split('-');

                foreach (string character in payloadArray)
                {
                    converted += new String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
                }

            }

            return converted;
        }

        public static byte[] IntToByteArray2(int number)
        {
            byte[] data = BitConverter.GetBytes(number);
            Array.Reverse(data);
            return data.Skip(2).ToArray();
        }

        public static string GetRecordType(byte[] data)
        {
            string type = "";

            switch (BitConverter.ToString(data))
            {

                case "00-01":
                    type = "A";
                    break;

                case "00-1C":
                    type = "AAAA";
                    break;

                case "00-05":
                    type = "CNAME";
                    break;

                case "00-27":
                    type = "DNAME";
                    break;

                case "00-0F":
                    type = "MX";
                    break;

                case "00-02":
                    type = "NS";
                    break;

                case "00-0C":
                    type = "PTR";
                    break;

                case "00-06":
                    type = "SOA";
                    break;

                case "00-21":
                    type = "SRV";
                    break;

                case "00-10":
                    type = "TXT";
                    break;

                case "00-FF":
                    type = "ANY";
                    break;

            }

            return type;
        }

        public static string CheckRequest(string type, string request, string sourceIP, string mainIP, string requestType, string[] recordTypes, bool enabled)
        {
            string responseMessage = "response sent";
            bool isRepeat = false;
            bool domainIgnoreMatch = false;
            bool domainReplyMatch = false;
            string[] nameRequestSplit;
            string nameRequestHost = "";
            string domainIgnore = "";

            if (request.Contains("."))
            {
                nameRequestSplit = request.Split('.');
                nameRequestHost = nameRequestSplit[0];
            }
            else
            {
                nameRequestHost = request;
            }

            if (!Program.enabledSpooferRepeat)
            {

                if (String.Equals(type, "DNS"))
                {
                    string sourceIPCheck = sourceIP.Split('%')[0];
                    string mappedIP = "";
                    string host = "";

                    if (!Program.enabledSpooferRepeat)
                    {

                        foreach (string hostMapping in Program.hostList)
                        {
                            string[] hostArray = hostMapping.Split(',');

                            if (!String.IsNullOrEmpty(hostArray[1]) && String.Equals(hostArray[1].Split('%')[0], sourceIPCheck.Split('%')[0]))
                            {
                                host = hostArray[0].Split('.')[0].ToUpper();
                            }
                            else if (!String.IsNullOrEmpty(hostArray[2]) && String.Equals(hostArray[2], sourceIPCheck))
                            {
                                host = hostArray[0].Split('.')[0].ToUpper();
                            }

                        }

                        if (!String.IsNullOrEmpty(host))
                        {

                            foreach (string capture in Program.ntlmv2UsernameList)
                            {

                                if (!String.IsNullOrEmpty(capture.Split(',')[1]) && capture.Split(',')[1].StartsWith(host))
                                {
                                    mappedIP = capture.Split(',')[0];
                                }

                            }

                            if (String.IsNullOrEmpty(mappedIP))
                            {

                                foreach (string capture in Program.ntlmv1UsernameList)
                                {

                                    if (!String.IsNullOrEmpty(capture.Split(',')[1]) && capture.Split(',')[1].StartsWith(host))
                                    {
                                        mappedIP = capture.Split(',')[0];
                                    }

                                }

                            }

                            if (!String.IsNullOrEmpty(mappedIP))
                            {

                                foreach (string capture in Program.ntlmv2UsernameList)
                                {

                                    if (capture.StartsWith(mappedIP) && !capture.EndsWith("$"))
                                    {
                                        isRepeat = true;
                                    }

                                }

                                foreach (string capture in Program.ntlmv1UsernameList)
                                {

                                    if (capture.StartsWith(mappedIP) && !capture.EndsWith("$"))
                                    {
                                        isRepeat = true;
                                    }

                                }

                            }

                        }

                    }

                }                

            }

            if (String.Equals(type, "DNS") && request.Contains(".") && Program.argSpooferDomainsIgnore != null)
            {
                
                foreach (string domain in Program.argSpooferDomainsIgnore)
                {

                    if (!domainIgnoreMatch && request.ToUpper().EndsWith(String.Concat(".", domain)))
                    {
                        domainIgnoreMatch = true;
                        domainIgnore = domain;
                    }

                }

            }

            if (String.Equals(type, "DNS") && request.Contains(".") && Program.argSpooferDomainsReply != null)
            {

                foreach (string domain in Program.argSpooferDomainsReply)
                {

                    if (!domainReplyMatch && request.ToUpper().EndsWith(String.Concat(".", domain)))
                    {             
                        domainReplyMatch = true;
                    }

                }

            }

            if (Program.enabledInspect)
            {
                responseMessage = "inspect only";
            }
            else if ((!String.Equals(type, "DNS") && !enabled))
            {
                responseMessage = "spoofer disabled";
            }
            else if ((String.Equals(type, "DNS") && !enabled && !String.Equals(sourceIP, mainIP)))
            {
                responseMessage = "spoofer disabled";
            }
            else if(String.Equals(requestType[0], "MATCH") && String.Equals(type, "IPv4") && String.Equals(requestType, "AAAA") || String.Equals(type, "IPv6") && !String.Equals(requestType, "AAAA"))
            {
                responseMessage = String.Concat(requestType, " type ignored");
            }      
            else if (recordTypes != null && recordTypes.Length > 0 && (!Array.Exists(recordTypes, element => element == requestType.ToUpper())))
            {
                responseMessage = String.Concat(requestType, " replies disabled");
            }
            else if (Program.argSpooferHostsIgnore != null && Program.argSpooferHostsIgnore.Length > 0 && (Array.Exists(Program.argSpooferHostsIgnore, element => element == request.ToUpper()) ||
                (Array.Exists(Program.argSpooferHostsIgnore, element => element == nameRequestHost.ToUpper()))))
            {
                responseMessage = String.Concat(request, " is on ignore list");
            }
            else if (Program.argSpooferHostsReply != null && Program.argSpooferHostsReply.Length > 0 && (!Array.Exists(Program.argSpooferHostsReply, element => element == request.ToUpper()) &&
                (!Array.Exists(Program.argSpooferHostsReply, element => element == nameRequestHost.ToUpper()))))
            {
                responseMessage = String.Concat(request, " not on reply list");
            }
            else if (Program.argSpooferIPsIgnore != null && Array.Exists(Program.argSpooferIPsIgnore, element => element == sourceIP))
            {
                responseMessage = String.Concat(sourceIP, " is on ignore list");
            }
            else if (Program.argSpooferIPsReply != null && !Array.Exists(Program.argSpooferIPsReply, element => element == sourceIP))
            {
                responseMessage = String.Concat(sourceIP, " not on reply list");
            }
            else if(String.Equals(type, "NBNS") && String.Equals(sourceIP, mainIP))
            {
                responseMessage = "local query";
            }
            else if(String.Equals(type, "DNS") && domainIgnoreMatch)
            {
                responseMessage = String.Concat(domainIgnore, " is on ignore list");
            }
            else if (String.Equals(type, "DNS") && Program.argSpooferDomainsReply != null && !domainReplyMatch)
            {
                responseMessage = "domain not on reply list";
            }
            else if (isRepeat)
            {
                responseMessage = String.Concat("previous ", sourceIP, " capture");
            }
            else if (String.Equals(sourceIP, mainIP))
            {
                responseMessage = "outgoing query";
            }
            else if (String.Equals(type, "DNS") && Program.enabledDNSRelay)
            {
                responseMessage = "DNS relay";
            }

            return responseMessage;
        }

        public static UInt16 GetPacketChecksum(byte[] pseudoHeader, byte[] payload)
        {
            int e = 0;

            if((pseudoHeader.Length + payload.Length) % 2 != 0)
            {
                e = 1;
            }

            byte[] packet = new byte[pseudoHeader.Length + payload.Length + e];
            Buffer.BlockCopy(pseudoHeader, 0, packet, 0, pseudoHeader.Length);
            Buffer.BlockCopy(payload, 0, packet, pseudoHeader.Length, payload.Length);
            UInt32 packetChecksum = 0;
            int length = packet.Length;
            int index = 0;

            while ( index < length )
            {
                packetChecksum += Convert.ToUInt32(BitConverter.ToUInt16(packet, index));
                index += 2;
            }

            packetChecksum = (packetChecksum >> 16) + (packetChecksum & 0xffff);
            packetChecksum += (packetChecksum >> 16);

            return (UInt16)(~packetChecksum);
        }

        public static Byte[] GetIPv6PseudoHeader(IPAddress destinationIP, int nextHeader, int length)
        {
            byte[] lengthData = BitConverter.GetBytes(length);
            Array.Reverse(lengthData);
            byte[] pseudoHeader = new byte[40];
            Buffer.BlockCopy(Program.ipv6Address.GetAddressBytes(), 0, pseudoHeader, 0, 16);
            Buffer.BlockCopy(destinationIP.GetAddressBytes(), 0, pseudoHeader, 16, 16);
            Buffer.BlockCopy(lengthData, 0, pseudoHeader, 32, 4);
            pseudoHeader[39] = (byte)nextHeader;

            return pseudoHeader;
        }

        public static string GetLocalIPAddress(string ipVersion)
        {

            List<string> ipAddressList = new List<string>();
            AddressFamily addressFamily;

            if (String.Equals(ipVersion, "IPv4"))
            {
                addressFamily = AddressFamily.InterNetwork;
            }
            else
            {
                addressFamily = AddressFamily.InterNetworkV6;
            }

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == addressFamily)
                        {
                            ipAddressList.Add(ip.Address.ToString());
                        }

                    }

                }

            }

            return ipAddressList.FirstOrDefault();
        }

        public static string GetLocalMACAddress(string ipAddress)
        {
            List<string> macAddressList = new List<string>();

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == AddressFamily.InterNetworkV6 && String.Equals(ip.Address.ToString(), ipAddress))
                        {
                            macAddressList.Add(networkInterface.GetPhysicalAddress().ToString());
                        }

                    }

                }

            }

            return macAddressList.FirstOrDefault();
        }

        public static string GetLocalDNSAddress(string ipVersion, string ipAddress)
        {
            AddressFamily addressFamily = AddressFamily.InterNetwork;

            if (String.Equals(ipVersion, "IPv6"))
            {
                addressFamily = AddressFamily.InterNetworkV6;
            }

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == addressFamily && String.Equals(ip.Address.ToString(), ipAddress))
                        {
                            IPAddressCollection ipAddressCollection = networkInterface.GetIPProperties().DnsAddresses;
                            return ipAddressCollection.ToArray().FirstOrDefault().ToString();
                        }

                    }

                }

            }

            return null;
        }

        public static byte[] NewDNSNameArray(string name, bool addByte)
        {
            var indexList = new List<int>();

            for (int i = name.IndexOf('.'); i > -1; i = name.IndexOf('.', i + 1))
            {
                indexList.Add(i);
            }

            using (MemoryStream nameMemoryStream = new MemoryStream())
            {
                string nameSection = "";
                int nameStart = 0;

                if (indexList.Count > 0)
                {
                    int nameEnd = 0;

                    foreach (int index in indexList)
                    {
                        nameEnd = index - nameStart;
                        nameMemoryStream.Write(BitConverter.GetBytes(nameEnd), 0, 1);
                        nameSection = name.Substring(nameStart, nameEnd);
                        nameMemoryStream.Write(Encoding.UTF8.GetBytes(nameSection), 0, nameSection.Length);
                        nameStart = index + 1;
                    }

                }

                nameSection = name.Substring(nameStart);
                nameMemoryStream.Write(BitConverter.GetBytes(nameSection.Length), 0, 1);
                nameMemoryStream.Write(Encoding.UTF8.GetBytes(nameSection), 0, nameSection.Length);

                if (addByte)
                {
                    nameMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                }

                return nameMemoryStream.ToArray();
            }

        }

        public static void GetCleartextUnique()
        {
            string uniqueCleartextAccountLast = "";

            if (Program.cleartextList.Count > 0)
            {
                string[] outputCleartextUnique = Program.cleartextList.ToArray();
                Array.Sort(outputCleartextUnique);
                Console.WriteLine(String.Format("[+] [{0}] Current unique cleartext captures:", DateTime.Now.ToString("s")));

                foreach (string entry in outputCleartextUnique)
                {

                    if (!String.Equals(entry, uniqueCleartextAccountLast))
                    {
                        Console.WriteLine(entry);
                    }

                    uniqueCleartextAccountLast = entry;
                }

            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] Cleartext capture list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static void GetNTLMv1Unique()
        {
            string uniqueNTLMv1Account = "";
            string uniqueNTLMv1AccountLast = "";

            if (Program.ntlmv1List.Count > 0)
            {
                string[] outputNTLMV1Unique = Program.ntlmv1List.ToArray();
                Array.Sort(outputNTLMV1Unique);
                Console.WriteLine(String.Format("[+] [{0}] Current unique NTLMv1 challenge/response captures:", DateTime.Now.ToString("s")));

                foreach (string entry in outputNTLMV1Unique)
                {
                    uniqueNTLMv1Account = entry.Substring(0, entry.IndexOf(":", (entry.IndexOf(":") + 2)));

                    if (!String.Equals(uniqueNTLMv1Account, uniqueNTLMv1AccountLast))
                    {
                        Console.WriteLine(entry);
                    }

                    uniqueNTLMv1AccountLast = uniqueNTLMv1Account;
                }

            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] NTLMv1 challenge/response capture list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static void GetNTLMv2Unique()
        {
            string uniqueNTLMv2Account = "";
            string uniqueNTLMv2AccountLast = "";

            if (Program.ntlmv2List.Count > 0)
            {
                string[] outputNTLMV2Unique = Program.ntlmv2List.ToArray();
                Array.Sort(outputNTLMV2Unique);
                Console.WriteLine(String.Format("[+] [{0}] Current unique NTLMv2 challenge/response captures:", DateTime.Now.ToString("s")));

                foreach (string entry in outputNTLMV2Unique)
                {
                    uniqueNTLMv2Account = entry.Substring(0, entry.IndexOf(":", (entry.IndexOf(":") + 2)));

                    if (!String.Equals(uniqueNTLMv2Account, uniqueNTLMv2AccountLast))
                    {
                        Console.WriteLine(entry);
                    }

                    uniqueNTLMv2AccountLast = uniqueNTLMv2Account;
                }

            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] NTLMv2 challenge/response capture list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static void GetNTLMv1Usernames()
        {

            if (Program.ntlmv1UsernameList.Count > 0)
            {
                Console.WriteLine(String.Format("[+] [{0}] Current NTLMv1 IP addresses, hostnamess, and usernames:", DateTime.Now.ToString("s")));
                string[] outputNTLMV1Usernames = Program.ntlmv1UsernameList.ToArray();
                foreach (string entry in outputNTLMV1Usernames)
                    Console.WriteLine(entry);
            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] NTLMv1 IP address, hostname, and username list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static void GetNTLMv2Usernames()
        {

            if (Program.ntlmv2UsernameList.Count > 0)
            {
                Console.WriteLine(String.Format("[+] [{0}] Current NTLMv2 IP addresses, hostnames, and usernames:", DateTime.Now.ToString("s")));
                string[] outputNTLMV2Usernames = Program.ntlmv2UsernameList.ToArray();
                foreach (string entry in outputNTLMV2Usernames)
                    Console.WriteLine(entry);
            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] NTLMv2 IP address, hostname, and username list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static string ParseNameQuery(int index, byte[] data)
        {
            string hostname = "";
            byte[] queryLength = new byte[1];
            Buffer.BlockCopy(data, index, queryLength, 0, 1);
            int hostnameLength = queryLength[0];
            int i = 0;

            do
            {
                int hostnameSegmentLength = hostnameLength;
                byte[] hostnameSegment = new byte[hostnameSegmentLength];
                Buffer.BlockCopy(data, (index + 1), hostnameSegment, 0, hostnameSegmentLength);
                hostname += Encoding.UTF8.GetString(hostnameSegment);
                index += hostnameLength + 1;
                hostnameLength = data[index];
                i++;

                if (hostnameLength > 0)
                {
                    hostname += ".";
                }

            }
            while (hostnameLength != 0 && i <= 127);

            return hostname;
        }

        public static byte[] NewTimeStampArray()
        {
            string timestamp = BitConverter.ToString(BitConverter.GetBytes(Convert.ToInt64((DateTime.UtcNow - new DateTime(1601, 1, 1)).TotalHours)));
            byte[] timestampData = new byte[8];
            int i = 0;

            foreach (string character in timestamp.Split('-'))
            {
                timestampData[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                i++;
            }

            return timestampData;
        }

        public static void GetHelp(string arg)
        {
            bool nullarg = true;

            Console.WriteLine();

            if (String.IsNullOrEmpty(arg))
            {
                Console.WriteLine("args:\n");
            }
            else
            {
                Console.WriteLine("arg:\n");
                nullarg = false;
            }

            if (nullarg || String.Equals(arg, "CHALLENGE"))
            {
                Console.WriteLine(" -Challenge                  Default = Random: 16 character hex NTLM challenge for use with the HTTP listener.");
                Console.WriteLine("                             If left blank, a random challenge will be generated for each request.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "CONSOLE"))
            {
                Console.WriteLine(" -Console                    Default = 2: Set the output level. 0 = none, 1 = captures/spoofs only, 2 = all");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "CONSOLESTATUS"))
            {
                Console.WriteLine(" -ConsoleStatus              Default = Disabled: Interval in minutes for displaying all unique captured usernames,");
                Console.WriteLine("                             hashes, and credentials.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DHCPV6"))
            {
                Console.WriteLine(" -DHCPv6                     Default = Disabled: (Y/N) Enable/Disable DHCPv6 spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DHCPV6Local"))
            {
                Console.WriteLine(" -DHCPv6Local                Default = Disabled: (Y/N) Enable/Disable spoofing DHCPv6 packets from the Inveigh host.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DHCPV6DNSSUFFIX"))
            {
                Console.WriteLine(" -DHCPv6DNSSuffix            DNS search suffix to include in DHCPv6 responses.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DHCPV6RA"))
            {
                Console.WriteLine(" -DHCPv6RA                   Default = 30 Seconds: DHCPv6 ICMPv6 router advertise interval. Set to 0 to disable.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DNS"))
            {
                Console.WriteLine(" -DNS                        Default = Enabled: (Y/N) Enable/Disable DNS spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DNSHOSTNAME"))
            {
                Console.WriteLine(" -DNSHost                    Fully qualified hostname to use SOA/SRV responses.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DNSTTL"))
            {
                Console.WriteLine(" -DNSTTL                     Default = 30 Seconds: DNS TTL in seconds for the response packet.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "DNSTYPES"))
            {
                Console.WriteLine(" -DNSTypes                   Default = A: Comma separated list of DNS types to spoof. Types include A, SOA, and SRV");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "ELEVATEDPRIVILEGE"))
            {
                Console.WriteLine(" -Elevated                   Default = Y: (Y/N) Set the privilege mode. Elevated privilege features require an");
                Console.WriteLine("                             elevated administrator shell.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "FILEOUTPUT"))
            {
                Console.WriteLine(" -FileOutput                 Default = Disabled: (Y/N) Enable/Disable real time file output.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "FILEOUTPUTDIRECTORY"))
            {
                Console.WriteLine(" -FileOutputDirectory        Default = Working Directory: Valid path to an output directory for log and capture");
                Console.WriteLine("                             files. FileOutput must also be enabled.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "FILEPREFIX"))
            {
                Console.WriteLine(" -FilePrefix                 Default = Inveigh: Prefix for all output files.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "FILEUNIQUE"))
            {
                Console.WriteLine(" -FileUnique                 Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for");
                Console.WriteLine("                             only unique IP, domain/hostname, and username combinations when real time file");
                Console.WriteLine("                             output is enabled.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "HTTP"))
            {
                Console.WriteLine(" -HTTP                       Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "HTTPAUTH"))
            {
                Console.WriteLine(" -HTTPAuth                   Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authentication");
                Console.WriteLine("                             type. This setting does not apply to wpad.dat requests. NTLMNoESS turns off the");
                Console.WriteLine("                             'Extended Session Security' flag during negotiation.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "HTTPIP"))
            {
                Console.WriteLine(" -HTTPIP                     Default = Any: IP address for the HTTP/HTTPS listener.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "HTTPPORT"))
            {
                Console.WriteLine(" -HTTPPort                   Default = 80: TCP port for the HTTP listener.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "HTTPRESPONSE"))
            {
                Console.WriteLine(" -HTTPResponse               Content to serve as the default HTTP/HTTPS/Proxy response. This response will not be");
                Console.WriteLine("                             used for wpad.dat requests. This parameter will not be used if HTTPDir is set. Use C#");
                Console.WriteLine("                             character escapes and newlines where necessary.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "INSPECT"))
            {
                Console.WriteLine(" -Inspect                    (Switch) Inspect DNS/LLMNR/mDNS/NBNS/SMB traffic only.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "IP"))
            {
                Console.WriteLine(" -IP                         Local IP address for listening and packet sniffing. This IP address will also be");
                Console.WriteLine("                             used for spoofing if the SpooferIP arg is not set.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "IPV6"))
            {
                Console.WriteLine(" -IPv6                       Local IPv6 address for listening and packet sniffing. This IP address will also be");
                Console.WriteLine("                             used for spoofing if the SpooferIPv6 arg is not set.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "LLMNR"))
            {
                Console.WriteLine(" -LLMNR                      Default = Enabled: (Y/N) Enable/Disable LLMNR spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "LLMNRv6"))
            {
                Console.WriteLine(" -LLMNRv6                    Default = Disabled: (Y/N) Enable/Disable IPv6 LLMNR spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "LLMNRTTL"))
            {
                Console.WriteLine(" -LLMNRTTL                   Default = 30 Seconds: LLMNR TTL in seconds for the response packet.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "MAC"))
            {
                Console.WriteLine(" -MAC                        Local MAC address for IPv6.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "MACHINEACCOUNTS"))
            {
                Console.WriteLine(" -MachineAccounts            Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures");
                Console.WriteLine("                             from machine accounts.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "MDNS"))
            {
                Console.WriteLine(" -mDNS                       Default = Disabled: (Y/N) Enable/Disable mDNS spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "MDNSTTL"))
            {
                Console.WriteLine(" -mDNSTTL                    Default = 120 Seconds: mDNS TTL in seconds for the response packet.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "MDNSQuestions"))
            {
                Console.WriteLine(" -mDNSQuestions              Default = QU,QM: Comma separated list of mDNS question types to spoof. Note that QM will");
                Console.WriteLine("                             send the response to 224.0.0.251. Types include QU = Query Unicast, QM = Query Multicast");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "MDNSTYPES"))
            {
                Console.WriteLine(" -mDNSTypes                  Default = A: Comma separated list of mDNS record types to spoof.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "NBNS"))
            {
                Console.WriteLine(" -NBNS                       Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "NBNSTTL"))
            {
                Console.WriteLine(" -NBNSTTL                    Default = 165 Seconds: NBNS TTL in seconds for the response packet.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "NBNSTYPES"))
            {
                Console.WriteLine(" -NBNSTypes                  Default = 00,20: Comma separated list of NBNS types to spoof. Note, not all types have");
                Console.WriteLine("                             been tested. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server");
                Console.WriteLine("                             Service, 1B = Domain Name");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PCAP"))
            {
                Console.WriteLine(" -Pcap                       Default = Disabled: (Y/N) Enable/Disable IPv4 TCP/UDP pcap output.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PCAPPORTTCP"))
            {
                Console.WriteLine(" -PcapPortTCP                Default = 139,445: Comma separated list of TCP ports to filter which packets will be");
                Console.WriteLine("                             written to the pcap file. Use 'All' to capture on all ports.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PCAPPORTUDP"))
            {
                Console.WriteLine(" -PcapPortUDP                Default = Disabled: Comma separated list of UDP ports to filter which packets will be");
                Console.WriteLine("                             written to the pcap file. Use 'All' to capture on all ports.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PROXY"))
            {
                Console.WriteLine(" -Proxy                      Default = Disabled: (Y/N) Enable/Disable proxy listener authentication captures.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PROXYIP"))
            {
                Console.WriteLine(" -ProxyIP                    Default = Any: IP address for the proxy listener.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PROXYPORT"))
            {
                Console.WriteLine(" -ProxyPort                  Default = 8492: TCP port for the proxy listener.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "PROXYIGNORE"))
            {
                Console.WriteLine(" -ProxyIgnore                Default = Firefox: Comma separated list of keywords to use for filtering browser");
                Console.WriteLine("                             user agents. Matching browsers will not be sent the wpad.dat file used for capturing");
                Console.WriteLine("                             proxy authentications.Firefox does not work correctly with the proxy server failover");
                Console.WriteLine("                             setup. Firefox will be left unable to connect to any sites until the proxy is cleared.");
                Console.WriteLine("                             Remove 'Firefox' from this list to attack Firefox. If attacking Firefox, consider");
                Console.WriteLine("                             setting -SpooferRepeat N to limit attacks against a single target so that victims can");
                Console.WriteLine("                             recover Firefox connectivity by closing and reopening.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "RUNCOUNT"))
            {
                Console.WriteLine(" -RunCount                   Default = Unlimited: (Integer) Number of NTLMv1/NTLMv2 captures to perform before");
                Console.WriteLine("                             auto-exiting.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "RUNTIME"))
            {
                Console.WriteLine(" -RunTime                    Default = Disabled: Run time duration in minutes.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SMB"))
            {
                Console.WriteLine(" -SMB                        Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning,");
                Console.WriteLine("                             LLMNR/NBNS spoofing can still direct targets to the host system's SMB server.");
                Console.WriteLine("                             Block TCP ports 445/139 or kill the SMB services if you need to prevent login");
                Console.WriteLine("                             requests from being processed by the Inveigh host.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERDOMAINSIGNORE"))
            {
                Console.WriteLine(" -SpooferDomainsIgnore       Default = All: Comma separated list of requested domains to ignore when spoofing");
                Console.WriteLine("                             with DNS.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERDOMAINSREPLY"))
            {
                Console.WriteLine(" -SpooferDomainsReply        Default = All: Comma separated list of requested domains to respond to when spoofing");
                Console.WriteLine("                             with DNS.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERHOSTSIGNORE"))
            {
                Console.WriteLine(" -SpooferHostsIgnore         Default = All: Comma separated list of requested hostnames to ignore when spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERHOSTSREPLY"))
            {
                Console.WriteLine(" -SpooferHostsReply          Default = All: Comma separated list of requested hostnames to respond to when spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERIP"))
            {
                Console.WriteLine(" -SpooferIP                  IP address for spoofing. This arg is only necessary when redirecting victims to a system");
                Console.WriteLine("                             other than the Inveigh host.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERIPV6"))
            {
                Console.WriteLine(" -SpooferIPv6                IPv6 address for DHCPv6/LLMNR spoofing. This arg is only necessary when redirecting");
                Console.WriteLine("                             victims to a system other than the Inveigh host. For DHCPv6, this will be the assigned");
                Console.WriteLine("                             DNS server IP.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERIPSIGNORE"))
            {
                Console.WriteLine(" -SpooferIPsIgnore           Default = All: Comma separated list of source IP addresses to ignore when spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERIPSREPLY"))
            {
                Console.WriteLine(" -SpooferIPsReply            Default = All: Comma separated list of source IP addresses to respond to when spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERMACSIGNORE"))
            {
                Console.WriteLine(" -SpooferMACsIgnore          Default = All: Comma separated list of MAC addresses to ignore when DHCPv6 spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERMACSREPLY"))
            {
                Console.WriteLine(" -SpooferMACsReply           Default = All: Comma separated list of MAC addresses to respond to when DHCPv6 spoofing.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "SPOOFERREPEAT"))
            {
                Console.WriteLine(" -SpooferRepeat              Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/ NBNS spoofs to a victim system");
                Console.WriteLine("                             after one user challenge/response has been captured.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADAUTH"))
            {
                Console.WriteLine(" -WPADAuth                   Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authentication type");
                Console.WriteLine("                             for wpad.dat requests. Setting to Anonymous can prevent browser login prompts. NTLMNoESS ");
                Console.WriteLine("                             turns off the 'Extended Session Security' flag during negotiation.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADDNSDOMAINISHOSTSDIRECT"))
            {
                Console.WriteLine(" -WPADdnsDomainIsHostsDirect Comma separated list of hosts to setup as direct in the wpad.dat file when using");
                Console.WriteLine("                             proxy auth or specifying a proxy server. See PAC file dnsDomainIs function for details.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADDNSDOMAINISHOSTSPROXY"))
            {
                Console.WriteLine(" -WPADdnsDomainIsHostsProxy  Comma separated list of hosts to send through proxy in the wpad.dat file when using");
                Console.WriteLine("                             proxy auth or specifying a proxy server. See PAC file dnsDomainIs function for details.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADIP"))
            {
                Console.WriteLine(" -WPADIP                     Proxy server IP to be included in the wpad.dat response for WPAD enabled browsers. This");
                Console.WriteLine("                             parameter must be used with WPADPort.");
                Console.WriteLine();
            }


            if (nullarg || String.Equals(arg, "WPADPORT"))
            {
                Console.WriteLine(" -WPADPort                   Proxy server port to be included in the wpad.dat response for WPAD enabled browsers.");
                Console.WriteLine("                             This parameter must be used with WPADIP.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADRESPONSE"))
            {
                Console.WriteLine(" -WPADResponse               wpad.dat file contents to serve as the wpad.dat response. This parameter will not be");
                Console.WriteLine("                             used if WPADIP and WPADPort are set. Use C# character escapes where necessary.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADSHEXPMATCHHOSTSDIRECT"))
            {
                Console.WriteLine(" -WPADshExpMatchHostsDirect  Comma separated list of hosts with wildcards to setup as direct in the wpad.dat file");
                Console.WriteLine("                             when using proxy auth or specifying a proxy server. See PAC file shExpMatch function");
                Console.WriteLine("                             for details.");
            }

            if (nullarg || String.Equals(arg, "WPADSHEXPMATCHHOSTSPROXY"))
            {
                Console.WriteLine(" -WPADshExpMatchHostsDirect  Comma separated list of hosts with wildcard to send to through proxy in the wpad.dat");
                Console.WriteLine("                             file when using proxy auth or specifying a proxy server. See PAC file shExpMatch function");
                Console.WriteLine("                             for details.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADSHEXPMATCHURLSDIRECT"))
            {
                Console.WriteLine(" -WPADshExpMatchURLsDirect   Comma separated list of URLs with wildcards to setup as direct in the wpad.dat file");
                Console.WriteLine("                             when using proxy auth or specifying a proxy server. See PAC file shExpMatch function");
                Console.WriteLine("                             for details.");
                Console.WriteLine();
            }

            if (nullarg || String.Equals(arg, "WPADSHEXPMATCHURLSPROXY"))
            {
                Console.WriteLine(" -WPADshExpMatchURLsProxy    Comma seperated list of URLs with wildcards to send through proxy in the wpad.dat file");
                Console.WriteLine("                             when using proxy auth or specifying a proxy server. See PAC file shExpMatch function");
                Console.WriteLine("                             for details.");
            }

            Console.WriteLine();
        }

        public static void ValidateStringArguments(string[] arguments, string[] values, string[] validValues)
        {
            int i = 0;
            foreach (string value in values)
            {

                if (!validValues.Contains(value))
                {
                    Console.WriteLine(arguments[i].Substring(3) + " value must be " + String.Join("/", validValues));
                    Environment.Exit(0);
                }

                i++;
            }

        }

        public static void ValidateStringArrayArguments(string argument, string[] values, string[] validValues)
        {

            foreach (string value in values)
            {

                if (!validValues.Contains(value))
                {
                    Console.WriteLine(argument.Substring(3) + " value must be " + String.Join("/", validValues));
                    Environment.Exit(0);
                }

            }

        }

        public static void ValidateIntArguments(string[] arguments, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!String.IsNullOrEmpty(value))
                {
                    try
                    {
                        Int32.Parse(value);

                    }
                    catch
                    {
                        Console.WriteLine(arguments[i].Substring(3) + " value must be an integer");
                        Environment.Exit(0);
                    }

                }

                i++;
            }

        }

        public static void ValidateIPAddressArguments(string[] arguments, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!String.IsNullOrEmpty(value))
                {

                    try
                    {
                        IPAddress.Parse(value);
                        
                    }
                    catch
                    {
                        Console.WriteLine(arguments[i].Substring(3) + " value must be an IP address");
                        Environment.Exit(0);
                    }

                }

                i++;
            }

        }

    }

}
