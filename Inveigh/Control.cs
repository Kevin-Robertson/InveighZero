using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Inveigh
{
    class Control
    {

        public static void FileOutput(string directory, string prefix)
        {

            while (true)
            {

                try
                {

                    if (Program.logFileList.Count > 0)
                    {

                        using (StreamWriter outputFileLog = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-Log.txt")), true))
                        {
                            outputFileLog.WriteLine(Program.logFileList[0]);
                            outputFileLog.Close();

                            lock (Program.logFileList)
                            {
                                Program.logFileList.RemoveAt(0);
                            }

                        }

                    }

                    if (Program.cleartextFileList.Count > 0)
                    {

                        using (StreamWriter outputFileCleartext = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-Cleartext.txt")), true))
                        {
                            outputFileCleartext.WriteLine(Program.cleartextFileList[0]);
                            outputFileCleartext.Close();

                            lock (Program.cleartextFileList)
                            {
                                Program.cleartextFileList.RemoveAt(0);
                            }

                        }

                    }

                    if (Program.ntlmv1FileList.Count > 0)
                    {

                        using (StreamWriter outputFileNTLMv1 = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-NTLMv1.txt")), true))
                        {
                            outputFileNTLMv1.WriteLine(Program.ntlmv1FileList[0]);
                            outputFileNTLMv1.Close();

                            lock (Program.ntlmv1FileList)
                            {
                                Program.ntlmv1FileList.RemoveAt(0);
                            }

                        }

                    }

                    if (Program.ntlmv2FileList.Count > 0)
                    {

                        using (StreamWriter outputFileNTLMv2 = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-NTLMv2.txt")), true))
                        {
                            outputFileNTLMv2.WriteLine(Program.ntlmv2FileList[0]);
                            outputFileNTLMv2.Close();

                            lock (Program.ntlmv2FileList)
                            {
                                Program.ntlmv2FileList.RemoveAt(0);
                            }

                        }

                    }

                    if (Program.ntlmv1UsernameFileList.Count > 0)
                    {

                        using (StreamWriter outputUsernameFileNTLMv1 = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-NTLMv1Users.txt")), true))
                        {
                            outputUsernameFileNTLMv1.WriteLine(Program.ntlmv1UsernameFileList[0]);
                            outputUsernameFileNTLMv1.Close();

                            lock (Program.ntlmv1UsernameList)
                            {
                                Program.ntlmv1UsernameFileList.RemoveAt(0);
                            }

                        }

                    }

                    if (Program.ntlmv2UsernameFileList.Count > 0)
                    {

                        using (StreamWriter outputUsernameFileNTLMv2 = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-NTLMv2Users.txt")), true))
                        {
                            outputUsernameFileNTLMv2.WriteLine(Program.ntlmv2UsernameFileList[0]);
                            outputUsernameFileNTLMv2.Close();

                            lock (Program.ntlmv2UsernameFileList)
                            {
                                Program.ntlmv2UsernameFileList.RemoveAt(0);
                            }

                        }

                    }

                    if (Program.hostFileList.Count > 0)
                    {

                        using (StreamWriter outputDHCPv6File = new StreamWriter(Path.Combine(directory, String.Concat(prefix, "-DHCPv6.txt")), true))
                        {
                            outputDHCPv6File.WriteLine(Program.hostFileList[0]);
                            outputDHCPv6File.Close();

                            lock (Program.hostFileList)
                            {
                                Program.hostFileList.RemoveAt(0);
                            }

                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] File output error detected - {1}", DateTime.Now.ToString("s"), ex.Message));
                }

                Thread.Sleep(200);
            }

        }

        public static void OutputLoop()
        {
            bool keyDetect = true;
            bool keyPressed = false;

            do
            {

                while (Program.consoleOutput && !keyPressed)
                {

                    try
                    {

                        if (keyDetect && Console.KeyAvailable)
                        {
                            keyPressed = true;
                        }

                    }
                    catch { keyDetect = false; }

                    while (Program.consoleList.Count > 0)
                    {
                        ConsoleOutputFormat(Program.consoleList[0]);
                        Program.consoleList.RemoveAt(0);
                    }

                    Thread.Sleep(5);
                }

            } while (Program.consoleOutput && Console.ReadKey(true).Key != ConsoleKey.Escape);

        }

        public static void ConsoleOutputFormat(string consoleEntry)
        {

            if (String.IsNullOrEmpty(consoleEntry))
            {
                consoleEntry = "";
            }

            if (consoleEntry.StartsWith("[*]") || consoleEntry.Contains(" captured ") || consoleEntry.Contains(" challenge ") || consoleEntry.Contains(" renewed to ") || consoleEntry.Contains(" leased to ") || 
                consoleEntry.Contains(" advertised to ") || consoleEntry.Contains("[not unique]") || consoleEntry.Contains("[redacted]") || (!consoleEntry.StartsWith("[+]") && !consoleEntry.StartsWith("[*]") && 
                !consoleEntry.StartsWith("[!]") && !consoleEntry.StartsWith("[-] ") && !consoleEntry.StartsWith("[.]")) && !consoleEntry.Contains("[machine account]"))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(consoleEntry);
                Console.ResetColor();
            }
            else if (consoleEntry.StartsWith("[!]"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(consoleEntry);
                Console.ResetColor();
            }
            else if (consoleEntry.Contains(" written to ") || consoleEntry.Contains(" ignored ") || consoleEntry.Contains("[machine account]"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(consoleEntry);
                Console.ResetColor();
            }
            else if (consoleEntry.Contains("response sent]") || consoleEntry.Contains("[advertised ") || consoleEntry.Contains("[assigned "))
            {
                Console.Write("[");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("+");
                Console.ResetColor();
                Console.Write("]");
                consoleEntry = consoleEntry.Substring(3);
                int outputIndex = (consoleEntry.Substring(5)).IndexOf("[") + 6;
                string outputStart = consoleEntry.Substring(0, outputIndex);
                string outputEnd = consoleEntry.Substring(outputIndex).Replace("]", "");
                Console.Write(outputStart);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(outputEnd);
                Console.ResetColor();
                Console.WriteLine("]");
            }
            else if (consoleEntry.StartsWith("[+]"))
            {
                Console.Write("[");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("+");
                Console.ResetColor();
                Console.WriteLine("]" + consoleEntry.Substring(3));
            }
            else
            {
                Console.WriteLine(consoleEntry);
            }

        }

        public static void ControlLoop(string consoleLevel, int consoleQueueLimit, int consoleStatus, int runCount, int runTime)
        {
            Stopwatch stopwatchConsoleStatus = new Stopwatch();
            stopwatchConsoleStatus.Start();
            Stopwatch stopwatchRunTime = new Stopwatch();
            stopwatchRunTime.Start();

            while (true)
            {

                if (consoleStatus > 0 && Program.consoleOutput && stopwatchConsoleStatus.Elapsed.Minutes >= consoleStatus)
                {
                    Util.GetCleartextUnique();
                    Util.GetNTLMv1Unique();
                    Util.GetNTLMv1Usernames();
                    Util.GetNTLMv2Unique();
                    Util.GetNTLMv2Usernames();
                    stopwatchConsoleStatus.Reset();
                    stopwatchConsoleStatus.Start();
                }

                if (runTime > 0 && Program.consoleOutput && stopwatchRunTime.Elapsed.Minutes >= runTime)
                {
                    Program.outputList.Add(String.Format("[*] {0} Inveigh is exiting due to reaching run time", DateTime.Now.ToString("s")));
                    Program.exitInveigh = true;
                    StopInveigh();
                }

                if (runCount > 0 && Program.consoleOutput && (Program.ntlmv1List.Count >= runCount || Program.ntlmv2List.Count >= runCount))
                {
                    Program.outputList.Add(String.Format("[*] {0} Inveigh is exiting due to reaching run count", DateTime.Now.ToString("s")));
                    Program.exitInveigh = true;
                    StopInveigh();
                }

                try
                {

                    while (Program.outputList.Count > 0)
                    {

                        if (Program.console == 3 && (Program.outputList[0].StartsWith("[+]") || Program.outputList[0].StartsWith("[*]") || Program.outputList[0].StartsWith("[.]") || Program.outputList[0].StartsWith("[!]") || Program.outputList[0].StartsWith("[-]") || Program.outputList[0].StartsWith("[not unique]") || !Program.outputList[0].StartsWith("[")))
                        {
                            Program.consoleList.Add(Program.outputList[0]);
                        }

                        if (Program.console == 2 && (!Program.outputList[0].Contains(" disabled]") || !Program.outputList[0].StartsWith("[")))
                        {
                            Program.consoleList.Add(Program.outputList[0]);
                        }

                        if (Program.console == 1 && (Program.outputList[0].StartsWith("[+]") || !Program.outputList[0].StartsWith("[") || Program.outputList[0].StartsWith("[not unique]") || !Program.outputList[0].StartsWith("[")))
                        {
                            Program.consoleList.Add(Program.outputList[0]);
                        }

                        if (Program.enabledLogOutput)
                        {
                            Program.logList.Add(Program.outputList[0]);
                        }

                        if (Program.outputList[0].StartsWith("[+]") || Program.outputList[0].StartsWith("[*]") || Program.outputList[0].StartsWith("[!]") || Program.outputList[0].StartsWith("[-]"))
                        {
                            Program.logFileList.Add(Program.outputList[0]);
                        }
                        else
                        {
                            Program.logFileList.Add("[redacted]");
                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.RemoveAt(0);
                        }

                    }

                    if (!Program.consoleOutput && consoleQueueLimit >= 0)
                    {

                        while (Program.consoleList.Count > consoleQueueLimit && !Program.consoleOutput)
                        {
                            Program.consoleList.RemoveAt(0);
                        }

                    }

                    if (Program.exitInveigh && Program.consoleOutput)
                    {
                        while (Program.consoleList.Count > 0)
                        {
                            Thread.Sleep(5);
                        }

                        Environment.Exit(0);
                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] Output error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

                Thread.Sleep(5);
            }

        }

        public static void StartupOutput()
        {

            if (Program.enabledDHCPv6 && !Program.enabledDNSv6)
            {
                Program.outputList.Add("[!] Enabled DNSv6 when using DHCPv6 with a local SpooferIPv6");
            }

            string optionStatus = "";
            Program.outputList.Add(String.Format("[*] Inveigh {0} started at {1}", Program.version, DateTime.Now.ToString("s")));

            if (Program.enabledWindows)
            {
                if (Program.enabledElevated) optionStatus = "+";
                else optionStatus = "-";
                Program.outputList.Add(String.Format("[{0}] Elevated Privilege Mode", optionStatus));
            }

            if (Program.enabledInspect) { Program.outputList.Add("[+] Inspect Only Mode"); }
            Program.outputList.Add(String.Format("[+] Primary IP Address = {0}", Program.argIP));
            if (!String.IsNullOrEmpty(Program.argIPv6)) Program.outputList.Add(String.Format("[+] Primary IPv6 Address = {0}", Program.argIPv6));
            Program.outputList.Add(String.Format("[+] Spoofer IP Address = {0}", Program.argSpooferIP));
            if (!String.IsNullOrEmpty(Program.argSpooferIPv6)) Program.outputList.Add(String.Format("[+] Spoofer IPv6 Address = {0}", Program.argSpooferIPv6));
            if (!String.IsNullOrEmpty(Program.argMAC)) Program.outputList.Add(String.Format("[+] Spoofer MAC Address = {0}", Program.argMAC));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferDomainsIgnore)) Program.outputList.Add(String.Format("[+] Spoofer Domain Ignore = {0}", String.Join(",", Program.argSpooferDomainsIgnore)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferDomainsReply)) Program.outputList.Add(String.Format("[+] Spoofer Domains Reply = {0}", String.Join(",", Program.argSpooferDomainsReply)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferHostsIgnore)) Program.outputList.Add(String.Format("[+] Spoofer Hosts Ignore = {0}", String.Join(",", Program.argSpooferHostsIgnore)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferHostsReply)) Program.outputList.Add(String.Format("[+] Spoofer Hosts Reply = {0}", String.Join(",", Program.argSpooferHostsReply)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferIPsIgnore)) Program.outputList.Add(String.Format("[+] Spoofer IPs Ignore = {0}", String.Join(",", Program.argSpooferIPsIgnore)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferIPsReply)) Program.outputList.Add(String.Format("[+] Spoofer IPs Reply = {0}", String.Join(",", Program.argSpooferIPsReply)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferMACsIgnore)) Program.outputList.Add(String.Format("[+] Spoofer MACs Ignore = {0}", String.Join(",", Program.argSpooferMACsIgnore)));
            if (!Util.ArrayIsNullOrEmpty(Program.argSpooferMACsReply)) Program.outputList.Add(String.Format("[+] Spoofer MACs Reply = {0}", String.Join(",", Program.argSpooferMACsReply)));
            if (Program.enabledElevated) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] Packet Sniffer", optionStatus));
            if (Program.enabledDHCPv6) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] DHCPv6 Spoofer", optionStatus));

            if (Program.enabledDHCPv6)
            {
                if (Program.enabledDHCPv6Local) optionStatus = "+";
                else optionStatus = "-";
                Program.outputList.Add(String.Format("[{0}] DHCPv6 Local Attacks", optionStatus));
                if (!String.IsNullOrEmpty(Program.argDHCPv6DNSSuffix)) Program.outputList.Add(String.Format("[+] DHCPv6 DNS Suffix = {0}", Program.argDHCPv6DNSSuffix));

            }

            if (Program.enabledICMPv6)
            {

                if (Program.enabledDHCPv6)
                {
                    Program.outputList.Add(String.Format("[+] ICMPv6 RA DHCPv6 Interval = {0} Seconds", Program.argICMPv6Interval));
                }
                else
                {
                    Program.outputList.Add(String.Format("[+] ICMPv6 RA DNS Interval = {0} Seconds", Program.argICMPv6Interval));
                }

            }

            if (Program.enabledDNS)
            {
                Program.outputList.Add(String.Format("[+] DNS Spoofer For Types {0}", String.Join(",", Program.argDNSTypes)));
                if (!String.IsNullOrEmpty(Program.argDNSHost)) { Program.outputList.Add(String.Format("[+] DNS Host = {0}", Program.argDNSHost)); }
            }
            else Program.outputList.Add(String.Format("[-] DNS Spoofer"));

            if (Program.enabledDNSv6)
            {
                Program.outputList.Add(String.Format("[+] DNSv6 Spoofer For Types {0}", String.Join(",", Program.argDNSTypes)));
                if (!String.IsNullOrEmpty(Program.argDNSHost)) { Program.outputList.Add(String.Format("[+] DNSv6 Host = {0}", Program.argDNSHost)); }
            }
            else Program.outputList.Add(String.Format("[-] DNSv6 Spoofer"));

            if (Program.enabledDNSRelay && (Program.enabledDNS || Program.enabledDNSv6))
            {
                Program.outputList.Add(String.Format("[+] DNS Relay to {0}", Program.dnsServerAddress.ToString()));
            }

            if (Program.enabledLLMNR) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] LLMNR Spoofer", optionStatus));
            if (Program.enabledLLMNRv6) optionStatus = "Enabled";
            else optionStatus = "Disabled";
            Program.outputList.Add(String.Format("[{0}] LLMNRv6 Spoofer", optionStatus));

            if (Program.enabledMDNS)
            {
                if (String.Equals(Program.argMDNSUnicast, "Y")) optionStatus = "Unicast Reply Only ";
                else optionStatus = "";
                Program.outputList.Add(String.Format("[+] mDNS({0}) {1}Spoofer For Types {2}", String.Join(",", Program.argMDNSQuestions), optionStatus, String.Join(",", Program.argMDNSTypes)));
            }
            else Program.outputList.Add(String.Format("[-] mDNS Spoofer"));

            if (Program.enabledMDNSv6)
            {
                if (String.Equals(Program.argMDNSUnicast, "Y")) optionStatus = "Unicast Reply Only ";
                else optionStatus = "";
                Program.outputList.Add(String.Format("[+] mDNSv6({0}) {1}Spoofer For Types {2}", String.Join(",", Program.argMDNSQuestions), optionStatus, String.Join(",", Program.argMDNSTypes)));
            }
            else Program.outputList.Add(String.Format("[-] mDNSv6 Spoofer"));

            if (Program.enabledNBNS)
            {
                Program.outputList.Add(String.Format("[+] NBNS Spoofer For Types {0}", String.Join(",", Program.argNBNSTypes)));
            }
            else Program.outputList.Add(String.Format("[-] NBNS Spoofer"));

            if (Program.enabledHTTP)
            {
                if (Program.argHTTPPorts.Length > 1) optionStatus = "Ports";
                else optionStatus = "Port";
                Program.outputList.Add(String.Format("[+] HTTP Capture On {0} {1}", optionStatus, String.Join(",", Program.argHTTPPorts)));
                if (!String.IsNullOrEmpty(Program.argChallenge)) Program.outputList.Add(String.Format("[+] HTTP NTLM Challenge = {0}", Program.argChallenge));
                Program.outputList.Add(String.Format("[+] HTTP Auth = {0}", Program.argHTTPAuth));
                if (!String.Equals(Program.argHTTPIP, "0.0.0.0")) Program.outputList.Add(String.Format("[+] HTTP IP = {0}", Program.argHTTPIP));
            }
            else
            {
                Program.outputList.Add(String.Format("[-] HTTP Capture"));
            }

            if (String.Equals(Program.argHTTPAuth, "BASIC") || String.Equals(Program.argProxyAuth, "BASIC") || String.Equals(Program.argWPADAuth, "BASIC")) { Program.outputList.Add(String.Format("[+] Basic Auth Realm = {0}", Program.argHTTPBasicRealm)); }

            if (Program.enabledProxy)
            {
                Program.outputList.Add(String.Format("[+] Proxy Auth Capture On Port {1}", optionStatus, Program.argProxyPort));
                if (!String.Equals(Program.argProxyIP, "0.0.0.0")) Program.outputList.Add(String.Format("[+] Proxy IP = {0}", Program.argProxyIP));
            }
            else
            {
                Program.outputList.Add(String.Format("[-] Proxy Auth Capture"));
            }

            Program.outputList.Add(String.Format("[+] WPAD Auth = {0}", Program.argWPADAuth));
            if (Program.argWPADAuth.StartsWith("NTLM")) Program.outputList.Add(String.Format("[+] WPAD NTLM Auth Ignore List = {0}", String.Join(",", Program.argWPADAuthIgnore)));
            //if (!Util.ArrayIsNullOrEmpty(argWPADDirectHosts)) outputList.Add(String.Format("[+] WPAD Direct Hosts = {0}", String.Join(",", argWPADDirectHosts))); // todo check
            if (!String.IsNullOrEmpty(Program.argWPADIP)) Program.outputList.Add(String.Format("[+] WPAD IP = {0}", Program.argWPADIP));
            if (!String.IsNullOrEmpty(Program.argWPADPort)) Program.outputList.Add(String.Format("[+] WPAD Port = {0}", Program.argWPADPort));
            if (Program.enabledSMB) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] SMB Capture", optionStatus));
            if (Program.enabledSMBv6) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] SMBv6 Capture", optionStatus));
            if (Program.enabledMachineAccounts) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] Machine Account Capture", optionStatus));
            if (Program.enabledFileOutput) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] File Output", optionStatus));
            if (Program.enabledLogOutput) optionStatus = "+";
            else optionStatus = "-";
            Program.outputList.Add(String.Format("[{0}] Log Output", optionStatus));
            if (Program.isSession) optionStatus = "Imported";
            else optionStatus = "Not Found";
            Program.outputList.Add(String.Format("[+] Previous Session Files = {0}", optionStatus));
            if (Program.enabledFileOutput) { Program.outputList.Add(String.Format("[+] Output Directory = {0}", Program.argFileOutputDirectory)); }
            if (Program.runCount == 1) Program.outputList.Add(String.Format("[+] Run Count = {0} Minute", Program.runCount));
            else if (Program.runCount > 1) Program.outputList.Add(String.Format("[+] Run Count = {0} Minutes", Program.runCount));
            if (Program.runTime == 1) Program.outputList.Add(String.Format("[+] Run Time = {0} Minute", Program.runTime));
            else if (Program.runTime > 1) Program.outputList.Add(String.Format("[+] Run Time = {0} Minutes", Program.runTime));
            Program.outputList.Add(String.Format("[*] Press ESC to access console"));
        }

        public static void StopInveigh()
        {
            Console.WriteLine(String.Format("[+] Inveigh exited at {0}", DateTime.Now.ToString("s")));
            Environment.Exit(0);
        }

        public static void ValidateArguments()
        {
            string[] ynArguments = { nameof(Program.argConsoleUnique), nameof(Program.argDHCPv6), nameof(Program.argDHCPv6Local), nameof(Program.argDNS), nameof(Program.argDNSv6), nameof(Program.argDNSRelay), nameof(Program.argFileOutput), nameof(Program.argFileUnique), nameof(Program.argHTTP), nameof(Program.argICMPv6), nameof(Program.argLLMNR), nameof(Program.argLLMNRv6), nameof(Program.argLogOutput), nameof(Program.argMachineAccounts), nameof(Program.argMDNS), nameof(Program.argMDNSv6), nameof(Program.argMDNSUnicast), nameof(Program.argNBNS), nameof(Program.argProxy), nameof(Program.argSMB) };
            string[] ynArgumentValues = { Program.argConsoleUnique, Program.argDHCPv6, Program.argDHCPv6Local, Program.argDNS, Program.argDNSv6, Program.argDNSRelay, Program.argFileOutput, Program.argFileUnique, Program.argHTTP, Program.argICMPv6, Program.argLLMNR, Program.argLLMNRv6, Program.argLogOutput, Program.argMachineAccounts, Program.argMDNS, Program.argMDNS, Program.argMDNSUnicast, Program.argNBNS, Program.argProxy, Program.argSMB };
            Util.ValidateStringArguments(ynArguments, ynArgumentValues, new string[] { "Y", "N" });
            Util.ValidateStringArguments(new string[] { nameof(Program.argConsole) }, new string[] { Program.argConsole }, new string[] { "0", "1", "2", "3" });
            string[] authArguments = { nameof(Program.argHTTPAuth), nameof(Program.argProxyAuth), nameof(Program.argWPADAuth) };
            string[] authArgumentValues = { Program.argHTTPAuth, Program.argProxyAuth, Program.argWPADAuth };
            Util.ValidateStringArguments(authArguments, new string[] { Program.argHTTPAuth, Program.argWPADAuth }, new string[] { "ANONYMOUS", "BASIC", "NTLM", "NTLMNOESS" });
            Util.ValidateStringArrayArguments(nameof(Program.argDNSTypes), Program.argDNSTypes, new string[] { "A", "SOA", "SRV" });
            Util.ValidateStringArrayArguments(nameof(Program.argNBNSTypes), Program.argNBNSTypes, new string[] { "00", "03", "20", "1B", "1C", "1D", "1E" });
            Util.ValidateStringArrayArguments(nameof(Program.argMDNSQuestions), Program.argMDNSQuestions, new string[] { "QM", "QU" });
            Util.ValidateStringArrayArguments(nameof(Program.argMDNSQuestions), Program.argMDNSTypes, new string[] { "A", "AAAA" });
            string[] intArguments = { nameof(Program.argConsole), nameof(Program.argConsoleQueueLimit), nameof(Program.argConsoleStatus), nameof(Program.argDNSTTL), nameof(Program.argICMPv6Interval), nameof(Program.argLLMNRTTL), nameof(Program.argMDNSTTL), nameof(Program.argNBNSTTL), nameof(Program.argProxyPort), nameof(Program.argRunCount), nameof(Program.argRunTime), nameof(Program.argWPADPort) };
            string[] intArgumentValues = { Program.argConsole, Program.argConsoleQueueLimit, Program.argConsoleStatus, Program.argDNSTTL, Program.argICMPv6Interval, Program.argLLMNRTTL, Program.argMDNSTTL, Program.argNBNSTTL, Program.argProxyPort, Program.argRunCount, Program.argRunTime, Program.argWPADPort };
            Util.ValidateIntArguments(intArguments, intArgumentValues);
            string[] ipAddressArguments = { nameof(Program.argIP), nameof(Program.argIPv6), nameof(Program.argHTTPIP), nameof(Program.argProxyIP), nameof(Program.argSpooferIP), nameof(Program.argSpooferIPv6), nameof(Program.argWPADIP) };
            string[] ipAddressArgumentValues = { Program.argIP, Program.argIPv6, Program.argHTTPIP, Program.argProxyIP, Program.argSpooferIP, Program.argSpooferIPv6, Program.argWPADIP };
            Util.ValidateIPAddressArguments(ipAddressArguments, ipAddressArgumentValues);
            Util.ValidateIntArrayArguments(nameof(Program.argHTTPPorts), Program.argHTTPPorts);

            Regex r = new Regex("^[A-Fa-f0-9]{16}$"); if (!String.IsNullOrEmpty(Program.argChallenge) && !r.IsMatch(Program.argChallenge)) { Console.WriteLine("Challenge is invalid"); Environment.Exit(0); }
            r = new Regex("^[A-Fa-f0-9]{12}$"); if (!String.IsNullOrEmpty(Program.argMAC) && !r.IsMatch(Program.argMAC)) { Console.WriteLine("MAC address is invalid"); Environment.Exit(0); }
            if ((Program.argDNSTypes.Contains("SOA") || Program.argDNSTypes.Contains("SRV")) && (String.IsNullOrEmpty(Program.argDNSHost) || Program.argDNSHost.Split('.').Count() < 3)) { Console.WriteLine("DNSHost must be specified and fully qualified when using DNSTypes SOA or SRV"); Environment.Exit(0); }
            if (String.Equals(Program.argFileOutput, "Y") && !Directory.Exists(Program.argFileOutputDirectory)) { Console.WriteLine("FileOutputDirectory is invalid"); Environment.Exit(0); }
        }

    }

}
