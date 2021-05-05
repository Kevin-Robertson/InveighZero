/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
using System;
using System.Linq;

namespace Quiddity.Support
{
    class Utilities
    {

        public static byte[] BlockCopy(byte[] Data1, byte[] Data2)
        {
            byte[] data = new byte[Data1.Length + Data2.Length];
            Buffer.BlockCopy(Data1, 0, data, 0, Data1.Length);
            Buffer.BlockCopy(Data2, 0, data, Data1.Length, Data2.Length);
            return data;
        }

        public static byte[] BlockCopy(byte[] Data1, byte[] Data2, byte[] Data3)
        {
            byte[] data = new byte[Data1.Length + Data2.Length + Data3.Length];
            Buffer.BlockCopy(Data1, 0, data, 0, Data1.Length);
            Buffer.BlockCopy(Data2, 0, data, Data1.Length, Data2.Length);
            Buffer.BlockCopy(Data3, 0, data, (Data1.Length + Data2.Length), Data3.Length);
            return data;
        }

        public static string DataToString(int start, int length, byte[] data)
        {
            string converted = "";

            if (length > 0)
            {
                byte[] dataExtract = new byte[length - 1];
                Buffer.BlockCopy(data, start, dataExtract, 0, dataExtract.Length);
                string hex = BitConverter.ToString(dataExtract);
                hex = hex.Replace("-00", String.Empty);
                string[] payloadArray = hex.Split('-');

                foreach (string character in payloadArray)
                {
                    converted += new String(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
                }

            }

            return converted;
        }

        public static bool ArrayIsNullOrEmpty(Array array)
        {
            return (array == null || array.Length == 0);
        }

        public static ushort DataToUInt16(byte[] data)
        {
            return BitConverter.ToUInt16(data, 0);
        }

        public static byte[] IntToByteArray2(int number)
        {
            byte[] data = BitConverter.GetBytes(number);
            Array.Reverse(data);
            return data.Skip(2).ToArray();
        }

    }

}
