/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.Security.Cryptography;
using System.Text;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.Utils;

#if (NETCOREAPP3_0)
namespace CryptHash.Net.Encryption.AES.AEAD
{
    public class AEAD_AES_256_GCM
    {
        #region fields

        private static readonly int _keyBitSize = 256;
        private static readonly int _keyBytesLength = (_keyBitSize / 8);

        private const int _nonceBitSize = 96;
        private const int _nonceBytesLength = (_nonceBitSize / 8);

        private const int _tagBitSize = 128;
        private const int _tagBytesLength = (_tagBitSize / 8);

        // Maximum input size -> 2^39 - 256 bits
        // (long)((Math.Pow(2, 39) - 256) / 8) -> 68,719,476,704 bytes or ≅ 63.9 gigaBytes...
        private const long _maxInputDataSizeBytes = 68719476704;

        // Maximum input authenticated data size -> 2^64 - 1 bit
        // (long)((BigInteger.Pow(2, 64) - 1) / 8) -> 2,305,843,009,213,693,951 bytes or ≅ 2,147,483,647 gigaBytes or 2,097,151 teraBytes...
        private const long _maxInputAuthDataSizeBytes = 2305843009213693951;

        #endregion private fields


        #region internal methods

        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] key, byte[] nonce, byte[] associatedData = null)
        {
            if (plainStringBytes == null || plainStringBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (plainStringBytes.LongLength > _maxInputDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Max. string length cannot be greater than {_maxInputDataSizeBytes} bytes."
                };
            }

            if (key == null)
            {
                //key = new byte[32];
                //RandomNumberGenerator.Fill(key);
                key = EncryptionUtils.GenerateRandomBytes(_keyBytesLength);
            }

            if (key.Length != _keyBytesLength)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Invalid key bit size: ({(key.Length * 8)}). Must be ({_keyBitSize}) bits / ({_keyBytesLength}) bytes."
                };
            }

            if (nonce == null)
            {
                //nonce = new byte[12];
                //RandomNumberGenerator.Fill(nonce);
                nonce = EncryptionUtils.GenerateRandomBytes(_nonceBytesLength);
            }

            if (nonce.Length != _nonceBytesLength)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Invalid nonce bit size: ({(nonce.Length * 8)}). Must be ({_nonceBitSize}) bits / ({_nonceBytesLength}) bytes."
                };
            }

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
                };
            }

            byte[] tag = new byte[_tagBytesLength];
            byte[] encryptedData = new byte[plainStringBytes.Length];

            try
            {
                using (var aesGcm = new AesGcm(key))
                {
                    aesGcm.Encrypt(nonce, plainStringBytes, encryptedData, tag, associatedData);
                }

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = "Data succesfully encrypted.",
                    EncryptedDataBytes = encryptedData,
                    EncryptedDataBase64String = Convert.ToBase64String(encryptedData),
                    Tag = tag,
                    Key = key,
                    Nonce = nonce
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to encrypt data:\n{ex.ToString()}"
                };
            }
        }

        public AesEncryptionResult DecryptString(byte[] encryptedStringBytes, byte[] key, byte[] tag, byte[] nonce, byte[] associatedData = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to decrypt required."
                };
            }

            if (encryptedStringBytes.LongLength > _maxInputDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Max. encrypted data length cannot be greater than {_maxInputDataSizeBytes} bytes."
                };
            }

            if (key == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Encryption key required."
                };
            }

            if (key.Length != _keyBytesLength)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Invalid key bit size: ({(key.Length * 8)}). Must be ({_keyBitSize}) bits / ({_keyBytesLength}) bytes."
                };
            }

            if (tag == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Authentication Tag required."
                };
            }

            if (tag.Length != _tagBytesLength)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Invalid tag bit size: ({(tag.Length * 8)}). Must be: ({_tagBitSize}) bits / ({_tagBytesLength}) bytes."
                };
            }

            if (nonce == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Nonce required."
                };
            }

            if (nonce.Length != _nonceBytesLength)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Invalid nonce bit size: ({(nonce.Length * 8)}). Must be: ({_nonceBitSize}) bits / ({_nonceBytesLength}) bytes."
                };
            }

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
                };
            }

            byte[] decryptedData = new byte[encryptedStringBytes.Length];

            try
            {
                using (var aesGcm = new AesGcm(key))
                {
                    aesGcm.Decrypt(nonce, encryptedStringBytes, tag, decryptedData, associatedData);
                }

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = "Data succesfully decrypted.",
                    DecryptedDataBytes = decryptedData,
                    DecryptedDataString = Encoding.UTF8.GetString(decryptedData),
                    Tag = tag,
                    Key = key,
                    Nonce = nonce
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
                };
            }
        }

        #endregion public methods
    }
}
#endif