/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

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
    }
}
