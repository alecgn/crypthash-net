/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.AES.Enums;
using CryptHash.Net.Encryption.Utils;

#if (NETSTANDARD2_1 || NETCOREAPP3_0)
namespace CryptHash.Net.Encryption.AES.AEAD
{
    public class AEAD_AES_256_GCM
    {
        #region fields

        private static readonly int _keyBitSize = 256;
        private static readonly int _keyBytesLength = (_keyBitSize / 8);

        private static readonly int _saltBitSize = 128;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

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

        private static readonly int _iterationsForPBKDF2 = 100000;

        #endregion private fields


        #region public methods

        #region string encryption

        public AesEncryptionResult EncryptString(string plainString, string password, string associatedDataString = null, bool appendEncryptionDataToOutputString = true)
        {
            if (string.IsNullOrEmpty(plainString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (string.IsNullOrEmpty(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var plainStringBytes = Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutputString);
        }

        public AesEncryptionResult EncryptString(string plainString, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutputString = true)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var plainStringBytes = Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutputString);
        }

        public AesEncryptionResult EncryptString(byte[] plainStringBytes, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutputString = true)
        {
            if (plainStringBytes == null || plainStringBytes.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutputString);
        }

        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool appendEncryptionDataToOutputString = true)
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

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
                };
            }

            try
            {
                byte[] salt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);
                byte[] derivedKey = EncryptionUtils.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
                byte[] nonce = EncryptionUtils.GenerateRandomBytes(_nonceBytesLength);
                byte[] tag = new byte[_tagBytesLength];
                byte[] encryptedData = new byte[plainStringBytes.Length];

                using (var aesGcm = new AesGcm(derivedKey))
                {
                    aesGcm.Encrypt(nonce, plainStringBytes, encryptedData, tag, associatedData);
                }

                if (appendEncryptionDataToOutputString)
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var bw = new BinaryWriter(ms))
                        {
                            bw.Write(encryptedData);
                            bw.Write(nonce);
                            bw.Write(salt);
                            bw.Write(tag);
                        }

                        encryptedData = ms.ToArray();
                    }
                }

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = "Data succesfully encrypted.",
                    EncryptedDataBytes = encryptedData,
                    EncryptedDataBase64String = Convert.ToBase64String(encryptedData),
                    Tag = tag,
                    Key = derivedKey,
                    Nonce = nonce,
                    Salt = salt,
                    AesCipherMode = AesCipherMode.GCM
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

        //public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] key, byte[] nonce, byte[] associatedData = null, bool appendEncryptionDataToOutputString = true)
        //{
        //    if (plainStringBytes == null || plainStringBytes.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to encrypt required."
        //        };
        //    }

        //    if (plainStringBytes.LongLength > _maxInputDataSizeBytes)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Max. string length cannot be greater than {_maxInputDataSizeBytes} bytes."
        //        };
        //    }

        //    if (key == null)
        //    {
        //        //key = new byte[32];
        //        //RandomNumberGenerator.Fill(key);
        //        key = EncryptionUtils.GenerateRandomBytes(_keyBytesLength);
        //    }

        //    if (key.Length != _keyBytesLength)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Invalid key bit size: ({(key.Length * 8)}). Must be ({_keyBitSize}) bits / ({_keyBytesLength}) bytes."
        //        };
        //    }

        //    if (nonce == null)
        //    {
        //        //nonce = new byte[12];
        //        //RandomNumberGenerator.Fill(nonce);
        //        nonce = EncryptionUtils.GenerateRandomBytes(_nonceBytesLength);
        //    }

        //    if (nonce.Length != _nonceBytesLength)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Invalid nonce bit size: ({(nonce.Length * 8)}). Must be ({_nonceBitSize}) bits / ({_nonceBytesLength}) bytes."
        //        };
        //    }

        //    if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
        //        };
        //    }

        //    byte[] tag = new byte[_tagBytesLength];
        //    byte[] encryptedData = new byte[plainStringBytes.Length];

        //    try
        //    {
        //        using (var aesGcm = new AesGcm(key))
        //        {
        //            aesGcm.Encrypt(nonce, plainStringBytes, encryptedData, tag, associatedData);
        //        }

        //        return new AesEncryptionResult()
        //        {
        //            Success = true,
        //            Message = "Data succesfully encrypted.",
        //            EncryptedDataBytes = encryptedData,
        //            EncryptedDataBase64String = Convert.ToBase64String(encryptedData),
        //            Tag = tag,
        //            Key = key,
        //            Nonce = nonce
        //        };
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Error while trying to encrypt data:\n{ex.ToString()}"
        //        };
        //    }
        //}

        #endregion string encryption


        #region string decryption

        public AesDecryptionResult DecryptString(string base64EncryptedString, string password, string associatedDataString = null, bool hasEncryptionDataAppendedInInputString = true)
        {
            if (string.IsNullOrEmpty(base64EncryptedString))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "String to decrypt required."
                };
            }

            if (string.IsNullOrEmpty(password))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var encryptedStringBytes = Convert.FromBase64String(base64EncryptedString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInputString);
        }

        public AesDecryptionResult DecryptString(string base64EncryptedString, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInputString = true)
        {
            if (string.IsNullOrWhiteSpace(base64EncryptedString))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "String to decrypt required."
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var plainStringBytes = Encoding.UTF8.GetBytes(base64EncryptedString);
            var passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(plainStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInputString);
        }

        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInputString = true)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInputString);
        }

        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool hasEncryptionDataAppendedInInputString = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length == 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = "String to decrypt required."
                };
            }

            if (encryptedStringBytes.LongLength > _maxInputDataSizeBytes)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"Max. encrypted data length cannot be greater than {_maxInputDataSizeBytes} bytes."
                };
            }

            if (passwordBytes == null)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"Password required."
                };
            }

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
                };
            }

            try
            {
                byte[] encryptedStringBytesWithEncryptionData = null;

                if (hasEncryptionDataAppendedInInputString)
                {
                    tag = new byte[_tagBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength), tag, 0, tag.Length);

                    salt = new byte[_saltBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength), salt, 0, salt.Length);

                    nonce = new byte[_nonceBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _nonceBytesLength), nonce, 0, nonce.Length);

                    encryptedStringBytesWithEncryptionData = new byte[(encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _nonceBytesLength)];
                    Array.Copy(encryptedStringBytes, 0, encryptedStringBytesWithEncryptionData, 0, encryptedStringBytesWithEncryptionData.Length);
                }

                byte[] derivedKey = EncryptionUtils.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
                byte[] decryptedData = new byte[(hasEncryptionDataAppendedInInputString ? encryptedStringBytesWithEncryptionData.Length : encryptedStringBytes.Length)];

                using (var aesGcm = new AesGcm(derivedKey))
                {
                    aesGcm.Decrypt(nonce, (hasEncryptionDataAppendedInInputString ? encryptedStringBytesWithEncryptionData : encryptedStringBytes), tag, decryptedData, associatedData);
                }

                return new AesDecryptionResult()
                {
                    Success = true,
                    Message = "Data succesfully decrypted.",
                    DecryptedDataBytes = decryptedData,
                    DecryptedDataString = Encoding.UTF8.GetString(decryptedData),
                    Tag = tag,
                    Key = derivedKey,
                    Nonce = nonce,
                    Salt = salt,
                    AesCipherMode = AesCipherMode.GCM
                };
            }
            catch (Exception ex)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
                };
            }
        }

        //public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] key, byte[] tag, byte[] nonce, byte[] associatedData = null, bool hasEncryptionDataAppendedInInputString = true)
        //{
        //    if (encryptedStringBytes == null || encryptedStringBytes.Length == 0)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to decrypt required."
        //        };
        //    }

        //    if (encryptedStringBytes.LongLength > _maxInputDataSizeBytes)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Max. encrypted data length cannot be greater than {_maxInputDataSizeBytes} bytes."
        //        };
        //    }

        //    if (key == null)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Encryption key required."
        //        };
        //    }

        //    if (key.Length != _keyBytesLength)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Invalid key bit size: ({(key.Length * 8)}). Must be ({_keyBitSize}) bits / ({_keyBytesLength}) bytes."
        //        };
        //    }

        //    if (tag == null)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Authentication Tag required."
        //        };
        //    }

        //    if (tag.Length != _tagBytesLength)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Invalid tag bit size: ({(tag.Length * 8)}). Must be: ({_tagBitSize}) bits / ({_tagBytesLength}) bytes."
        //        };
        //    }

        //    if (nonce == null)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Nonce required."
        //        };
        //    }

        //    if (nonce.Length != _nonceBytesLength)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Invalid nonce bit size: ({(nonce.Length * 8)}). Must be: ({_nonceBitSize}) bits / ({_nonceBytesLength}) bytes."
        //        };
        //    }

        //    if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
        //        };
        //    }

        //    byte[] decryptedData = new byte[encryptedStringBytes.Length];

        //    try
        //    {
        //        using (var aesGcm = new AesGcm(key))
        //        {
        //            aesGcm.Decrypt(nonce, encryptedStringBytes, tag, decryptedData, associatedData);
        //        }

        //        return new AesDecryptionResult()
        //        {
        //            Success = true,
        //            Message = "Data succesfully decrypted.",
        //            DecryptedDataBytes = decryptedData,
        //            DecryptedDataString = Encoding.UTF8.GetString(decryptedData),
        //            Tag = tag,
        //            Key = key,
        //            Nonce = nonce
        //        };
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AesDecryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
        //        };
        //    }
        //}

        #endregion string decryption

        #endregion public methods
    }
}
#endif