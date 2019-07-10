using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Inveigh
{
    class Common
    {

        public static string HexStringToString(string hexString)
        {
            string[] stringArray = hexString.Split('-');
            string stringConverted = "";

            foreach (string character in stringArray)
            {
                stringConverted += new System.String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
            }

            return stringConverted;
        }

        public static uint UInt16DataLength(int start, byte[] field)
        {
            byte[] fieldExtract = new byte[2];

            if (field.Length > start + 2)
            {
                System.Buffer.BlockCopy(field, start, fieldExtract, 0, 2);
            }

            return BitConverter.ToUInt16(fieldExtract, 0);
        }

        public static uint UInt32DataLength(int start, byte[] field)
        {
            byte[] fieldExtract = new byte[4];
            System.Buffer.BlockCopy(field, start, fieldExtract, 0, 4);
            return BitConverter.ToUInt32(fieldExtract, 0);
        }

        public static uint DataToUInt16(byte[] field)
        {
            Array.Reverse(field);
            return BitConverter.ToUInt16(field, 0);
        }

        public static string DataToString(int start, int length, byte[] field)
        {
            string payloadConverted = "";

            if (length > 0)
            {
                byte[] fieldExtract = new byte[length - 1];
                System.Buffer.BlockCopy(field, start, fieldExtract, 0, fieldExtract.Length);
                string payload = System.BitConverter.ToString(fieldExtract);
                payload = payload.Replace("-00", String.Empty);
                string[] payloadArray = payload.Split('-');    

                foreach (string character in payloadArray)
                {
                    payloadConverted += new System.String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
                }

            }

            return payloadConverted;
        }

        public static byte[] IntToByteArray2(int field)
        {
            byte[] byteArray = BitConverter.GetBytes(field);
            Array.Reverse(byteArray);
            return byteArray.Skip(2).ToArray();
        }

        public static string CheckRequest(string nameRequest, string ipAddress)
        {
            string responseMessage = "response sent";

            if (Program.parameterSpooferHostsIgnore != null && Array.Exists(Program.parameterSpooferHostsIgnore, element => element == nameRequest.ToUpper()))
            {
                responseMessage = String.Concat(nameRequest, " is on ignore list");
            }
            else if (Program.parameterSpooferHostsReply != null && !Array.Exists(Program.parameterSpooferHostsReply, element => element == nameRequest.ToUpper()))
            {
                responseMessage = String.Concat(nameRequest, " not on reply list");
            }
            else if (Program.parameterSpooferIPsIgnore != null && Array.Exists(Program.parameterSpooferIPsIgnore, element => element == ipAddress))
            {
                responseMessage = String.Concat(ipAddress, " is on ignore list");
            }
            else if (Program.parameterSpooferIPsReply != null && !Array.Exists(Program.parameterSpooferIPsReply, element => element == ipAddress))
            {
                responseMessage = String.Concat(ipAddress, " not on reply list");
            }
            else if (Program.ipCaptureList.Contains(ipAddress.ToString()))
            {
                responseMessage = String.Concat("previous ", ipAddress, " capture");
            }

            return responseMessage;
        }

    }
}
