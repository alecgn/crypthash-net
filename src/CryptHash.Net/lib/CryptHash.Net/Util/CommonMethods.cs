/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Resources;
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace CryptHash.Net.Util
{
    public static class CommonMethods
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];

            using (var rngCSP = new RNGCryptoServiceProvider())
            {
                rngCSP.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        public static byte[] Generate128BitKey()
        {
            return GenerateRandomBytes(128 / 8);
        }

        public static byte[] GenerateSalt(int saltLength = 0)
        {
            return (saltLength == 0 ? Generate128BitKey() : GenerateRandomBytes(saltLength));
        }

        public static byte[] Generate256BitKey()
        {
            return GenerateRandomBytes(256 / 8);
        }

        public static byte[] GetHashedBytesFromPBKDF2(byte[] passwordBytes, byte[] saltBytes, int keyBytesLength, int iterations/*, HashAlgorithmName hashAlgorithmName*/)
        {
            byte[] pbkdf2HashedBytes;

            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations/*, hashAlgorithmName*/))
            {
                pbkdf2HashedBytes = pbkdf2.GetBytes(keyBytesLength);
            }

            return pbkdf2HashedBytes;
        }

#if NETSTANDARD2_1
        public static byte[] GetHashedBytesFromPBKDF2(byte[] passwordBytes, byte[] saltBytes, int keyBytesLength, int iterations, HashAlgorithmName hashAlgorithmName)
        {
            byte[] pbkdf2HashedBytes;

            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations, hashAlgorithmName))
            {
                pbkdf2HashedBytes = pbkdf2.GetBytes(keyBytesLength);
            }

            return pbkdf2HashedBytes;
        }
#endif

        public static byte[] ConvertSecureStringToByteArray(SecureString secString)
        {
            var byteArray = new byte[secString.Length];
            var bstr = IntPtr.Zero;

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
            {
                throw new FileNotFoundException($"{MessageStrings.Common_FileNotFound} {filePath}.", nameof(filePath));
            }

            File.SetAttributes(filePath, FileAttributes.Normal);
        }


        #region SHA256 methods

        //public static byte[] ComputeHMACSHA256HashFromFile(string filePath, byte[] authKey, int offset = 0)
        //{
        //    if (!File.Exists(filePath))
        //    {
        //        throw new FileNotFoundException($"{MessageStrings.Common_FileNotFound} {filePath}.", filePath);
        //    }

        //    if (authKey == null || authKey.Length == 0)
        //    {
        //        throw new ArgumentException($"{(MessageStrings.Common_InvalidAuthKeySizeError)} ({(authKey == null ? 0 : authKey.Length)}).", nameof(authKey));
        //    }

        //    byte[] hash = null;

        //    using (var hmacSha256 = new HMACSHA256(authKey))
        //    {
        //        using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        //        {
        //            fStream.Seek(offset, SeekOrigin.Begin);
        //            hash = hmacSha256.ComputeHash(fStream);
        //            fStream.Close();
        //        }
        //    }

        //    return hash;
        //}

        //public static byte[] ComputeHMACSHA256HashFromFile(string filePath, byte[] authKey, long startPosition, long endPosition)
        //{
        //    byte[] hash = null;

        //    using (var fStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
        //    {
        //        fStream.Position = startPosition;
        //        byte[] buffer = new byte[(1024 * 4)];
        //        long amount = (endPosition - startPosition);

        //        using (var hmacSha256 = new HMACSHA256(authKey))
        //        {
        //            while (amount > 0)
        //            {
        //                int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

        //                if (bytesRead > 0)
        //                {
        //                    amount -= bytesRead;

        //                    if (amount > 0)
        //                        hmacSha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);
        //                    else
        //                        hmacSha256.TransformFinalBlock(buffer, 0, bytesRead);
        //                }
        //                else
        //                    throw new InvalidOperationException();
        //            }

        //            hash = hmacSha256.Hash;
        //        }
        //    }

        //    return hash;
        //}

        //public static byte[] ComputeHMACSHA256HashFromDataBytes(byte[] authKey, byte[] dataBytes, int offset, int count)
        //{
        //    if (dataBytes == null || dataBytes.Length == 0)
        //    {
        //        throw new ArgumentException(MessageStrings.HMAC_InputRequired, nameof(dataBytes));
        //    }

        //    if (authKey == null || authKey.Length == 0)
        //    {
        //        throw new ArgumentException($"{MessageStrings.Common_InvalidAuthKeySizeError} ({(authKey == null ? 0 : authKey.Length)}).", nameof(authKey));
        //    }

        //    byte[] hash = null;

        //    using (var hmacSha256 = new HMACSHA256(authKey))
        //    {
        //        hash = hmacSha256.ComputeHash(dataBytes, offset, count);
        //    }

        //    return hash;
        //}

        #endregion SHA256 methods


        #region SHA384 methods

        //public static byte[] ComputeHMACSHA384HashFromFile(string filePath, byte[] authKey, int offset = 0)
        //{
        //    if (!File.Exists(filePath))
        //    {
        //        throw new FileNotFoundException($"{MessageStrings.Common_FileNotFound} {filePath}.", filePath);
        //    }

        //    if (authKey == null || authKey.Length == 0)
        //    {
        //        throw new ArgumentException($"{(MessageStrings.Common_InvalidAuthKeySizeError)} ({(authKey == null ? 0 : authKey.Length)}).", nameof(authKey));
        //    }

        //    byte[] hash = null;

        //    using (var hmacSha384 = new HMACSHA384(authKey))
        //    {
        //        using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        //        {
        //            fStream.Seek(offset, SeekOrigin.Begin);
        //            hash = hmacSha384.ComputeHash(fStream);
        //            fStream.Close();
        //        }
        //    }

        //    return hash;
        //}

        //public static byte[] ComputeHMACSHA384HashFromFile(string filePath, byte[] authKey, long startPosition, long endPosition)
        //{
        //    byte[] hash = null;

        //    using (var fStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
        //    {
        //        fStream.Position = startPosition;
        //        byte[] buffer = new byte[(1024 * 4)];
        //        long amount = (endPosition - startPosition);

        //        using (var hmacSha384 = new HMACSHA384(authKey))
        //        {
        //            while (amount > 0)
        //            {
        //                int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

        //                if (bytesRead > 0)
        //                {
        //                    amount -= bytesRead;

        //                    if (amount > 0)
        //                        hmacSha384.TransformBlock(buffer, 0, bytesRead, buffer, 0);
        //                    else
        //                        hmacSha384.TransformFinalBlock(buffer, 0, bytesRead);
        //                }
        //                else
        //                    throw new InvalidOperationException();
        //            }

        //            hash = hmacSha384.Hash;
        //        }
        //    }

        //    return hash;
        //}

        //public static byte[] ComputeHMACSHA384HashFromDataBytes(byte[] authKey, byte[] dataBytes, int offset, int count)
        //{
        //    if (dataBytes == null || dataBytes.Length == 0)
        //    {
        //        throw new ArgumentException(MessageStrings.HMAC_InputRequired, nameof(dataBytes));
        //    }

        //    if (authKey == null || authKey.Length == 0)
        //    {
        //        throw new ArgumentException($"{MessageStrings.Common_InvalidAuthKeySizeError} ({(authKey == null ? 0 : authKey.Length)}).", nameof(authKey));
        //    }

        //    byte[] hash = null;

        //    using (var hmacSha384 = new HMACSHA384(authKey))
        //    {
        //        hash = hmacSha384.ComputeHash(dataBytes, offset, count);
        //    }

        //    return hash;
        //}

        #endregion SHA384 methods


        #region SHA512 methods

        //public static byte[] ComputeHMACSHA512HashFromFile(string filePath, byte[] authKey, int offset = 0)
        //{
        //    if (!File.Exists(filePath))
        //    {
        //        throw new FileNotFoundException($"{MessageStrings.Common_FileNotFound} {filePath}.", filePath);
        //    }

        //    if (authKey == null || authKey.Length == 0)
        //    {
        //        throw new ArgumentException($"{(MessageStrings.Common_InvalidAuthKeySizeError)} ({(authKey == null ? 0 : authKey.Length)}).", nameof(authKey));
        //    }

        //    byte[] hash = null;

        //    using (var hmacSha512 = new HMACSHA512(authKey))
        //    {
        //        using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        //        {
        //            fStream.Seek(offset, SeekOrigin.Begin);
        //            hash = hmacSha512.ComputeHash(fStream);
        //            fStream.Close();
        //        }
        //    }

        //    return hash;
        //}

        //public static byte[] ComputeHMACSHA512HashFromFile(string filePath, byte[] authKey, long startPosition, long endPosition)
        //{
        //    byte[] hash = null;

        //    using (var fStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
        //    {
        //        fStream.Position = startPosition;
        //        byte[] buffer = new byte[(1024 * 4)];
        //        long amount = (endPosition - startPosition);

        //        using (var hmacSha512 = new HMACSHA512(authKey))
        //        {
        //            while (amount > 0)
        //            {
        //                int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

        //                if (bytesRead > 0)
        //                {
        //                    amount -= bytesRead;

        //                    if (amount > 0)
        //                        hmacSha512.TransformBlock(buffer, 0, bytesRead, buffer, 0);
        //                    else
        //                        hmacSha512.TransformFinalBlock(buffer, 0, bytesRead);
        //                }
        //                else
        //                    throw new InvalidOperationException();
        //            }

        //            hash = hmacSha512.Hash;
        //        }
        //    }

        //    return hash;
        //}

        //public static byte[] ComputeHMACSHA512HashFromDataBytes(byte[] authKey, byte[] dataBytes, int offset, int count)
        //{
        //    if (dataBytes == null || dataBytes.Length == 0)
        //    {
        //        throw new ArgumentException(MessageStrings.HMAC_InputRequired, nameof(dataBytes));
        //    }

        //    if (authKey == null || authKey.Length == 0)
        //    {
        //        throw new ArgumentException($"{MessageStrings.Common_InvalidAuthKeySizeError} ({(authKey == null ? 0 : authKey.Length)}).", nameof(authKey));
        //    }

        //    byte[] hash = null;

        //    using (var hmacSha512 = new HMACSHA512(authKey))
        //    {
        //        hash = hmacSha512.ComputeHash(dataBytes, offset, count);
        //    }

        //    return hash;
        //}

        #endregion SHA512 methods


        public static void AppendDataBytesToFile(string filePath, byte[] dataBytes)
        {
            using (var fs = File.Open(filePath, FileMode.Append, FileAccess.Write, FileShare.None))
            {
                fs.Write(dataBytes, 0, dataBytes.Length);
            }
        }

        public static byte[] GetBytesFromFile(string filePath, int dataLength, long offset = 0)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"{MessageStrings.Common_FileNotFound} {filePath}.", filePath);
            }

            if (dataLength < 1)
            {
                throw new ArgumentException($"{MessageStrings.Common_InvalidDataLengthError} ({dataLength}).", nameof(dataLength));
            }

            var dataBytes = new byte[dataLength];

            using (var fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fStream.Seek(offset, SeekOrigin.Begin);
                fStream.Read(dataBytes, 0, dataLength);
                fStream.Close();
            }

            return dataBytes;
        }

        public static bool TagsMatch(byte[] calcTag, byte[] sentTag)
        {
            if (calcTag.Length != sentTag.Length)
            {
                throw new ArgumentException(MessageStrings.Common_IncorrectTagsLength);
            }

            var result = true;
            var compare = 0;

            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }

            if (compare != 0)
            {
                result = false;
            }

            return result;
        }
    }
}
