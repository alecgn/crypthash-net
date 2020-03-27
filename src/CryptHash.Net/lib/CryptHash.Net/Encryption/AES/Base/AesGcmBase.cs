/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.AES.Enums;
using CryptHash.Net.Util;
using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;

#if NETSTANDARD2_1
namespace CryptHash.Net.Encryption.AES.AEAD
{
    public abstract class AesGcmBase
    {
        #region fields

        private int _keyBitSize;
        internal int KeyBitSize
        {
            get => _keyBitSize;
            set
            {
                _keyBitSize = value;
                _keyBytesLength = (_keyBitSize / 8);
            }
        }

        private int _keyBytesLength;

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


        #region constructors

        internal AesGcmBase(int keyBitSize)
        {
            if (new int[] { 128, 192, 256 }.Contains(keyBitSize))
                KeyBitSize = keyBitSize;
            else
                throw new ArgumentException($"{MessageDictionary.Instance["Common.InvalidKeySizeError"]} ({keyBitSize}).", nameof(keyBitSize));
        }

        #endregion constructors


        #region public methods

        #region string encryption
        internal AesEncryptionResult EncryptString(string plainString, string password, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            if (string.IsNullOrEmpty(plainString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            if (string.IsNullOrEmpty(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutput);
        }

        internal AesEncryptionResult EncryptString(string plainString, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutput);
        }

        internal AesEncryptionResult EncryptString(byte[] plainStringBytes, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            if (plainStringBytes == null || plainStringBytes.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutput);
        }

        internal AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool appendEncryptionDataToOutput = true)
        {
            if (plainStringBytes == null || plainStringBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            if (plainStringBytes.LongLength > _maxInputDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Encryption.MaxInputSizeError"]}: ({_maxInputDataSizeBytes})."
                };
            }

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Encryption.MaxAssociatedDataSizeError"]} ({_maxInputAuthDataSizeBytes})."
                };
            }

            try
            {
                //byte[] salt = CommonMethods.GenerateRandomBytes(_saltBytesLength);
                byte[] salt = CommonMethods.GenerateSalt();
                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
                byte[] nonce = CommonMethods.GenerateRandomBytes(_nonceBytesLength);
                byte[] tag = new byte[_tagBytesLength];
                byte[] encryptedData = new byte[plainStringBytes.Length];

                using (var aesGcm = new AesGcm(derivedKey))
                {
                    aesGcm.Encrypt(nonce, plainStringBytes, encryptedData, tag, associatedData);
                }

                if (appendEncryptionDataToOutput)
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
                    Message = MessageDictionary.Instance["Encryption.EncryptSuccess"],
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
                    Message = $"{MessageDictionary.Instance["Encryption.ExceptionError"]}\n{ex.ToString()}"
                };
            }
        }

        #endregion string encryption


        #region string decryption

        internal AesDecryptionResult DecryptString(string base64EncryptedString, string password, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (string.IsNullOrEmpty(base64EncryptedString))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            if (string.IsNullOrEmpty(password))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var encryptedStringBytes = Convert.FromBase64String(base64EncryptedString);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        internal AesDecryptionResult DecryptString(string base64EncryptedString, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (string.IsNullOrWhiteSpace(base64EncryptedString))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(base64EncryptedString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(plainStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        internal AesDecryptionResult DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        internal AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length == 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            if (encryptedStringBytes.LongLength > _maxInputDataSizeBytes)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Decryption.MaxEncryptedInputSizeError"]} ({_maxInputDataSizeBytes})."
                };
            }

            if (passwordBytes == null)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Encryption.MaxAssociatedDataSizeError"]} ({_maxInputAuthDataSizeBytes})."
                };
            }

            try
            {
                byte[] encryptedStringBytesWithEncryptionData = null;

                if (hasEncryptionDataAppendedInInput)
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

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
                byte[] decryptedData = new byte[(hasEncryptionDataAppendedInInput ? encryptedStringBytesWithEncryptionData.Length : encryptedStringBytes.Length)];

                using (var aesGcm = new AesGcm(derivedKey))
                {
                    aesGcm.Decrypt(nonce, (hasEncryptionDataAppendedInInput ? encryptedStringBytesWithEncryptionData : encryptedStringBytes), tag, decryptedData, associatedData);
                }

                return new AesDecryptionResult()
                {
                    Success = true,
                    Message = MessageDictionary.Instance["Decryption.DecryptSuccess"],
                    DecryptedDataBytes = decryptedData,
                    DecryptedDataString = System.Text.Encoding.UTF8.GetString(decryptedData),
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
                    Message = $"{MessageDictionary.Instance["Decryption.ExceptionError"]}\n{ex.ToString()}"
                };
            }
        }

#endregion string decryption

#endregion public methods
    }
}
#endif