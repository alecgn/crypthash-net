/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.Utils.EventHandlers;
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
        #region Events

        public static event OnEncryptionProgressHandler OnEncryptionProgress;

        #endregion

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
        public static byte[] GetBytesFromPBKDF2(byte[] passwordBytes, byte[] saltBytes, int keyBytesLength, int iterations/*, HashAlgorithmName hashAlgorithmName*/)
        {
            byte[] pbkdf2HashedBytes;

            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations/*, hashAlgorithmName*/))
            {
                pbkdf2HashedBytes = pbkdf2.GetBytes(keyBytesLength);
            }

            return pbkdf2HashedBytes;
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

        public static byte[] CalculateHMACSHA256FromFile(string filePath, byte[] authKey, int bytesToIgnore = 0)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File \"{filePath}\" not found.", filePath);
            }

            if (authKey == null || authKey.Length == 0)
            {
                throw new ArgumentException("Invalid auth key.", nameof(authKey));
            }

            byte[] tag = null;

            using (HMACSHA256 hmacsha256 = new HMACSHA256(authKey))
            {
                using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    fStream.Seek(bytesToIgnore, SeekOrigin.Begin);
                    tag = hmacsha256.ComputeHash(fStream);
                    fStream.Close();
                }
            }

            return tag;
        }

        public static byte[] CalculateHMACSHA256FromDataBytes(byte[] authKey, byte[] dataBytes, int offset, int count)
        {
            if (dataBytes == null || dataBytes.Length == 0)
            {
                throw new ArgumentException("Invalid auth key.", nameof(authKey));
            }

            if (authKey == null || authKey.Length == 0)
            {
                throw new ArgumentException("Invalid data bytes.", nameof(authKey));
            }

            byte[] tag = null;

            using (var hmacSha256 = new HMACSHA256(authKey))
            {
                tag = hmacSha256.ComputeHash(dataBytes, offset, count);
            }

            return tag;
        }

        public static void WriteTagToFile(string filePath, byte[] fileSignature, int kBbufferSize = 4)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File \"{filePath}\" not found.", filePath);
            }

            if (fileSignature != null && fileSignature.Length <= 0)
            {
                throw new ArgumentException("Signature invalid.", nameof(fileSignature));
            }

            using (FileStream oldFile = System.IO.File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (FileStream newFile = System.IO.File.Open(filePath + ".signed", FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    newFile.Write(fileSignature, 0, fileSignature.Length);
                    //oldFile.CopyTo(newFile);

                    byte[] buffer = new byte[kBbufferSize * 1024];
                    int read;

                    while ((read = oldFile.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        newFile.Write(buffer, 0, read);

                        int percentageDone = (int)(oldFile.Position * 100 / oldFile.Length);
                        RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? "Writing authentication tag to encrypted file..." : "Write authentication tag to encrypted file done."));
                    }

                    newFile.Close();
                }
            }

            File.Delete(filePath);
            File.Move(filePath + ".signed", filePath);
        }

        public static byte[] GetBytesFromFile(string filePath, int dataLength, int dataPosition = 0)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File \"{filePath}\" not found.", filePath);
            }

            if (dataLength < 1)
            {
                throw new ArgumentException("Data length invalid.", nameof(dataLength));
            }

            byte[] dataBytes = new byte[dataLength];

            using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fStream.Seek(dataPosition, SeekOrigin.Begin);
                fStream.Read(dataBytes, 0, dataLength);
                fStream.Close();
            }

            return dataBytes;
        }

        public static bool TagsMatch(byte[] calcTag, byte[] sentTag)
        {
            if (calcTag.Length != sentTag.Length)
                throw new ArgumentException("Signature CalcTag and SentTag length must be igual.");

            var result = true;
            var compare = 0;

            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }

            if (compare != 0)
                result = false;

            return result;
        }

        private static void RaiseOnEncryptionProgress(int percentageDone, string message)
        {
            OnEncryptionProgress?.Invoke(percentageDone, message);
        }
    }
}
