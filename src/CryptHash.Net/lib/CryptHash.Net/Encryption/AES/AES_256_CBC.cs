using CryptHash.Net.Encryption.AES.Base;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.Utils;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptHash.Net.Encryption.AES
{
    public class AES_256_CBC : AesBase
    {
        private static readonly int _blockBitSize = 128;
        //private static readonly int _blockBytesLength = (_blockBitSize / 8);

        private static readonly int _IVBitSize = 128;
        private static readonly int _IVBytesLength = (_IVBitSize / 8);

        private static readonly int _keyBitSize = 256;
        private static readonly int _keyBytesLength = (_keyBitSize / 8);

        private static readonly int _feedbackSize = 128;

        private static readonly int _saltBitSize = 256;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

        private static readonly int _iterationsForPBKDF2 = 100000;

        private static readonly CipherMode _cipherMode = CipherMode.CBC;
        private static readonly PaddingMode _paddingMode = PaddingMode.PKCS7;

        public AES_256_CBC() : base() { }

        public AES_256_CBC(byte[] key, byte[] IV)
            : base(_keyBitSize, key, _blockBitSize, IV, _cipherMode, _paddingMode, _feedbackSize) { }

        public AesEncryptionResult EncryptString(byte[] stringToEncryptBytes, byte[] passwordBytes)
        {
            byte[] salt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);
            
            // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
            byte[] key = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, _keyBytesLength, salt, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

            var aesEncryptionResult = base.EncryptWithMemoryStream(stringToEncryptBytes, _keyBitSize, key, _blockBitSize, null, _cipherMode, _paddingMode, _feedbackSize);

            if (aesEncryptionResult.Success)
            {
                using (var ms = new MemoryStream())
                {
                    using (var bw = new BinaryWriter(ms))
                    {
                        bw.Write(salt);
                        bw.Write(aesEncryptionResult.IVOrNonce);
                        bw.Write(aesEncryptionResult.EncryptedDataBytes);
                    }

                    aesEncryptionResult.EncryptedDataBytes = ms.ToArray();
                    aesEncryptionResult.EncryptedDataString = Convert.ToBase64String(aesEncryptionResult.EncryptedDataBytes);
                }
            }

            return aesEncryptionResult;
        }

        public AesEncryptionResult DecryptString(byte[] stringToDecryptBytes, byte[] passwordBytes)
        {
            byte[] salt = new byte[_saltBytesLength];
            Array.Copy(stringToDecryptBytes, 0, salt, 0, salt.Length);

            // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
            byte[] key = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, _keyBytesLength, salt, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

            byte[] IV = new byte[_IVBytesLength];
            Array.Copy(stringToDecryptBytes, salt.Length, IV, 0, IV.Length);

            byte[] encryptedStringData = new byte[(stringToDecryptBytes.Length - salt.Length - IV.Length)];
            Array.Copy(stringToDecryptBytes, (salt.Length + IV.Length), encryptedStringData, 0, encryptedStringData.Length);

            var aesDecriptionResult = base.DecryptWithMemoryStream(encryptedStringData, _keyBitSize, key, _blockBitSize, IV, _cipherMode, _paddingMode, _feedbackSize);

            if (aesDecriptionResult.Success)
                aesDecriptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecriptionResult.DecryptedDataBytes);

            return aesDecriptionResult;
        }

        public AesEncryptionResult EncryptFile()
        {
            return base.EncryptWithFileStream();
        }

        public AesEncryptionResult DecryptFile()
        {
            return base.DecryptWithFileStream();
        }
    }
}
