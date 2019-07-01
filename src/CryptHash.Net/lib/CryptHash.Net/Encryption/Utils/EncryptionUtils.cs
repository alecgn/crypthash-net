/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.Utils
{
    public static class EncryptionUtils
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];

            using (RNGCryptoServiceProvider rngCSP = new RNGCryptoServiceProvider())
            {
                rngCSP.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        // waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
        public static byte[] GetBytesFromPBKDF2(byte[] passwordBytes, int keyBytesLength, byte[] saltBytes, int iterations/*, HashAlgorithmName hashAlgorithmName*/)
        {
            byte[] bytes;

            using (var PBKDF2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations/*, hashAlgorithmName*/))
            {
                bytes = PBKDF2.GetBytes(keyBytesLength);
            }

            return bytes;
        }

        public static byte[] ConvertSecureStringToByteArray(SecureString secString)
        {
            byte[] byteArray = new byte[secString.Length];
            IntPtr bstr = IntPtr.Zero;

            RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(
                    delegate
                    {
                        RuntimeHelpers.PrepareConstrainedRegions();
                        try { }
                        finally
                        {
                            bstr = Marshal.SecureStringToBSTR(secString);
                        }

                        Marshal.Copy(bstr, byteArray, 0, secString.Length);
                    },
                    delegate
                    {
                        if (bstr != IntPtr.Zero)
                        {
                            Marshal.ZeroFreeBSTR(bstr);
                            bstr = IntPtr.Zero;
                        }
                    },
                    null);

            return byteArray;
        }

        public static void ClearFileAttributes(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File {filePath} not found.", nameof(filePath));

            File.SetAttributes(filePath, FileAttributes.Normal);
        }

        public static byte[] CalculateFileSignature(string filePath, byte[] key, int bytesToIgnore = 0)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File \"{filePath}\" not found.", filePath);
            }

            if (key != null && key.Length <= 0)
            {
                throw new ArgumentException("Key invalid.", nameof(key));
            }

            byte[] fileSignature = null;

            using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
            {
                using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    fStream.Seek(bytesToIgnore, SeekOrigin.Begin);
                    fileSignature = hmacsha256.ComputeHash(fStream);
                    fStream.Close();
                }
            }

            return fileSignature;
        }
    }
}
