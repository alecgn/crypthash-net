/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Util;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CryptHash.Net.Encoding
{
    public static class Hexadecimal
    {
        public static string ToHexString(string plainString)
        {
            if (string.IsNullOrWhiteSpace(plainString))
                return null;

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(plainString);

            return ToHexString(plainStringBytes);
        }

        public static string ToHexString(byte[] byteArray)
        {
            if (byteArray == null || byteArray.Length <= 0)
                return null;

            //var sb = new StringBuilder();

            //for (int i = 0; i < byteArray.Length; i++)
            //{
            //    sb.Append(byteArray[i].ToString("X2"));
            //}

            //return sb.ToString();

            return string.Concat(byteArray.Select(b => b.ToString("X2")));
        }

        public static string ToString(string hexString)
        {
            if (string.IsNullOrWhiteSpace(hexString))
                return null;

            var byteArray = ToByteArray(hexString);

            return System.Text.Encoding.UTF8.GetString(byteArray);
        }

        public static byte[] ToByteArray(string hexString)
        {
            if (string.IsNullOrWhiteSpace(hexString))
                return null;

            if (hexString.Length % 2 != 0)
                throw new ArgumentException(MessageDictionary.Instance["Common.IncorrectHexadecimalString"], nameof(hexString));

            var byteArray = new byte[hexString.Length / 2];
            var i = 0;

            foreach (var hexVal in ChunkHexString(hexString))
            {
                byteArray[i] = Convert.ToByte(hexVal, 16);
                i++;
            }

            return byteArray;
        }

        private static IEnumerable<string> ChunkHexString(string hexString)
        {
            for (int i = 0; i < hexString.Length; i += 2)
                yield return hexString.Substring(i, 2);
        }
    }
}
