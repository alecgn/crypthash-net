/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using System;

namespace CryptHash.Net.Encoding
{
    public static class Base64
    {
        public static string ToBase64String(string plainString)
        {
            if (string.IsNullOrWhiteSpace(plainString))
                return null;

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(plainString);
            
            return ToBase64String(plainStringBytes);
        }

        public static string ToBase64String(byte[] byteArray)
        {
            if (byteArray == null || byteArray.Length <= 0)
                return null;

            return System.Convert.ToBase64String(byteArray);
        }

        public static string ToString(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
                return null;

            var byteArray = Convert.FromBase64String(base64String);

            return System.Text.Encoding.UTF8.GetString(byteArray);
        }

        public static byte[] ToByteArray(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
                return null;

            return System.Convert.FromBase64String(base64String);
        }
    }
}
