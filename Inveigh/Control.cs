using System;
using System.IO;
using System.Threading;
using System.Diagnostics;

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

        public static void StopInveigh()
        {

            if (Program.pcapFile != null)
            {
                Program.pcapFile.Close();
                Program.pcapFile.Dispose();
            }

            Console.WriteLine(String.Format("[+] Inveigh exited at {0}", DateTime.Now.ToString("s")));
            Environment.Exit(0);
        }

    }

}
