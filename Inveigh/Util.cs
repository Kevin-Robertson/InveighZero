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

        public static string HexStringToString(string hexString)
        {
            string[] stringArray = hexString.Split('-');
            string stringConverted = "";

            foreach (string character in stringArray)
            {
                stringConverted += new String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
            }

            return stringConverted;
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
            string payloadConverted = "";

            if (length > 0)
            {
                byte[] fieldExtract = new byte[length - 1];
                Buffer.BlockCopy(field, start, fieldExtract, 0, fieldExtract.Length);
                string payload = BitConverter.ToString(fieldExtract);
                payload = payload.Replace("-00", String.Empty);
                string[] payloadArray = payload.Split('-');

                foreach (string character in payloadArray)
                {
                    payloadConverted += new System.String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
                }

            }

            return payloadConverted;
        }

        public static byte[] IntToByteArray2(int field)
        {
            byte[] byteArray = BitConverter.GetBytes(field);
            Array.Reverse(byteArray);
            return byteArray.Skip(2).ToArray();
        }

        public static string GetRecordType(byte[] requestRecordType)
        {
            string recordType = "";

            switch (BitConverter.ToString(requestRecordType))
            {

                case "00-01":
                    recordType = "A";
                    break;

                case "00-1C":
                    recordType = "AAAA";
                    break;

                case "00-05":
                    recordType = "CNAME";
                    break;

                case "00-27":
                    recordType = "DNAME";
                    break;

                case "00-0F":
                    recordType = "MX";
                    break;

                case "00-02":
                    recordType = "NS";
                    break;

                case "00-0C":
                    recordType = "PTR";
                    break;

                case "00-06":
                    recordType = "SOA";
                    break;

                case "00-21":
                    recordType = "SRV";
                    break;

                case "00-10":
                    recordType = "TXT";
                    break;               

            }

            return recordType;
        }

        public static string CheckRequest(string nameRequest, string sourceIP, string mainIP, string type, string requestType, string[] recordTypes)
        {
            string responseMessage = "response sent";
            bool isRepeat = false;
            bool domainIgnoreMatch = false;
            bool domainReplyMatch = false;
            string[] nameRequestSplit;
            string nameRequestHost = "";
            string domainIgnore = "";

            if (nameRequest.Contains("."))
            {
                nameRequestSplit = nameRequest.Split('.');
                nameRequestHost = nameRequestSplit[0];
            }

            if (!Program.enabledSpooferRepeat)
            {

                foreach (string capture in Program.ntlmv2UsernameList)
                {

                    if (capture.StartsWith(sourceIP) && !capture.EndsWith("$"))
                    {
                        isRepeat = true;
                    }

                }

                foreach (string capture in Program.ntlmv1UsernameList)
                {

                    if (capture.StartsWith(sourceIP) && !capture.EndsWith("$"))
                    {
                        isRepeat = true;
                    }

                }

            }

            if (String.Equals(type, "DNS") && nameRequest.Contains(".") && Program.argSpooferDomainsIgnore != null)
            {
                
                foreach (string domain in Program.argSpooferDomainsIgnore)
                {

                    if (!domainIgnoreMatch && nameRequest.ToUpper().EndsWith(String.Concat(".", domain)))
                    {
                        domainIgnoreMatch = true;
                        domainIgnore = domain;
                    }

                }

            }

            if (String.Equals(type, "DNS") && nameRequest.Contains(".") && Program.argSpooferDomainsReply != null)
            {

                foreach (string domain in Program.argSpooferDomainsReply)
                {

                    if (!domainReplyMatch && nameRequest.ToUpper().EndsWith(String.Concat(".", domain)))
                    {             
                        domainReplyMatch = true;
                    }

                }

            }

            if (Program.enabledInspect)
            {
                responseMessage = "inspect only";
            }
            else if ((String.Equals(type, "LLMNR") && !Program.enabledLLMNR) || (String.Equals(type, "LLMNRv6") && !Program.enabledLLMNRv6) || (String.Equals(type, "NBNS") && !Program.enabledNBNS) ||
                (String.Equals(type, "MDNS") && !Program.enabledMDNS) || (String.Equals(type, "DNS") && !Program.enabledDNS && !String.Equals(sourceIP, mainIP)))
            {
                responseMessage = "spoofer disabled";
            }
            else if (recordTypes != null && recordTypes.Length > 0 && (!Array.Exists(recordTypes, element => element == requestType.ToUpper())))
            {
                responseMessage = String.Concat(requestType, " replies disabled");
            }
            else if (Program.argSpooferHostsIgnore != null && Program.argSpooferHostsIgnore.Length > 0 && (Array.Exists(Program.argSpooferHostsIgnore, element => element == nameRequest.ToUpper()) ||
                (!String.IsNullOrEmpty(nameRequestHost) && Array.Exists(Program.argSpooferHostsIgnore, element => element == nameRequestHost.ToUpper()))))
            {
                responseMessage = String.Concat(nameRequest, " is on ignore list");
            }
            else if (Program.argSpooferHostsReply != null && Program.argSpooferHostsReply.Length > 0 && (!Array.Exists(Program.argSpooferHostsReply, element => element == nameRequest.ToUpper()) &&
                (!String.IsNullOrEmpty(nameRequestHost) && !Array.Exists(Program.argSpooferHostsReply, element => element == nameRequestHost.ToUpper()))))
            {
                responseMessage = String.Concat(nameRequest, " not on reply list");
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

        public static Byte[] GetIPv6PseudoHeader(IPAddress sourceIP, IPAddress destinationIP, int nextHeader, int length)
        {
            byte[] lengthData = BitConverter.GetBytes(length);
            Array.Reverse(lengthData);
            byte[] pseudoHeader = new byte[40];
            Buffer.BlockCopy(sourceIP.GetAddressBytes(), 0, pseudoHeader, 0, 16);
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
                Console.WriteLine(String.Format("[+] [{0}] Current NTLMv1 IP addresses and usernames:", DateTime.Now.ToString("s")));
                string[] outputNTLMV1Usernames = Program.ntlmv1UsernameList.ToArray();
                foreach (string entry in outputNTLMV1Usernames)
                    Console.WriteLine(entry);
            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] NTLMv1 IP address and username list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static void GetNTLMv2Usernames()
        {

            if (Program.ntlmv2UsernameList.Count > 0)
            {
                Console.WriteLine(String.Format("[+] [{0}] Current NTLMv2 IP addresses and usernames:", DateTime.Now.ToString("s")));
                string[] outputNTLMV2Usernames = Program.ntlmv2UsernameList.ToArray();
                foreach (string entry in outputNTLMV2Usernames)
                    Console.WriteLine(entry);
            }
            else
            {
                Console.WriteLine(String.Format("[+] [{0}] NTLMv2 IP address and username list is empty", DateTime.Now.ToString("s")));
            }

        }

        public static string ParseNameQuery(int index, byte[] nameQuery)
        {
            string hostname = "";
            byte[] queryLength = new byte[1];
            System.Buffer.BlockCopy(nameQuery, index, queryLength, 0, 1);
            int hostnameLength = queryLength[0];
            int i = 0;

            do
            {
                int hostnameSegmentLength = hostnameLength;
                byte[] hostnameSegment = new byte[hostnameSegmentLength];
                System.Buffer.BlockCopy(nameQuery, (index + 1), hostnameSegment, 0, hostnameSegmentLength);
                hostname += Encoding.UTF8.GetString(hostnameSegment);
                index += hostnameLength + 1;
                hostnameLength = nameQuery[index];
                i++;

                if (hostnameLength > 0)
                {
                    hostname += ".";
                }

            }
            while (hostnameLength != 0 && i <= 127);

            return hostname;
        }

    }

}
