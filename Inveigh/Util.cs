using System;
using System.Linq;
using System.Text;

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
                stringConverted += new System.String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
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
                System.Buffer.BlockCopy(field, start, fieldExtract, 0, fieldExtract.Length);
                string payload = System.BitConverter.ToString(fieldExtract);
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

        public static string CheckRequest(string nameRequest, string sourceIP, string mainIP, string type)
        {
            string responseMessage = "response sent";
            bool isRepeat = false;
            string[] nameRequestSplit;
            string nameRequestHost = "";

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

            if (Program.enabledInspect)
            {
                responseMessage = "inspect only";
            }
            else if ((String.Equals(type, "LLMNR") && !Program.enabledLLMNR) || (String.Equals(type, "NBNS") && !Program.enabledNBNS) ||
                (String.Equals(type, "MDNS") && !Program.enabledMDNS) || (String.Equals(type, "DNS") && !Program.enabledDNS && !String.Equals(sourceIP, mainIP)))
            {
                responseMessage = "spoofer disabled";
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
            else if (isRepeat)
            {
                responseMessage = String.Concat("previous ", sourceIP, " capture");
            }

            return responseMessage;
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
