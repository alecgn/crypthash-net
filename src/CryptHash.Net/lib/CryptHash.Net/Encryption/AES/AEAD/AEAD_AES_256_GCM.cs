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
using CryptHash.Net.Util;

#if NETSTANDARD2_1
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

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="plainString">The input plain string to encrypt.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutputString">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(string plainString, string password, string associatedDataString = null, bool appendEncryptionDataToOutputString = true)
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

            var plainStringBytes = Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutputString);
        }

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="plainString">The input plain string to encrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutputString">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(string plainString, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutputString = true)
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

            var plainStringBytes = Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutputString);
        }

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutputString">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(byte[] plainStringBytes, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutputString = true)
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
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutputString);
        }

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="associatedData">The byte array of the encryption additional associated data used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutputString">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool appendEncryptionDataToOutputString = true)
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

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="base64EncryptedString">The base64 encoded input string to decrypt.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInputString">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptString(string base64EncryptedString, string password, string associatedDataString = null, bool hasEncryptionDataAppendedInInputString = true,
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
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInputString, tag, salt, nonce);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="base64EncryptedString">The base64 encoded input string to decrypt.</param>
        /// <param name="secStrPassword">The SecureString of the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInputString">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="tag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <param name="nonce">The previously generated byte array of the Nonce. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptString(string base64EncryptedString, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInputString = true,
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

            var plainStringBytes = Encoding.UTF8.GetBytes(base64EncryptedString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(plainStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInputString, tag, salt, nonce);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="encryptedStringBytes">The byte array of the input string to decrypt.</param>
        /// <param name="secStrPassword">The SecureString of the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInputString">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="tag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <param name="nonce">The previously generated byte array of the Nonce. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInputString = true,
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
            var associatedDataBytes = (associatedDataString == null ? null : Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInputString, tag, salt, nonce);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="encryptedStringBytes">The byte array of the input string to decrypt.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="associatedData">The byte array of the encryption additional associated data used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInputString">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="tag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <param name="nonce">The previously generated byte array of the Nonce. Leave empty or pass null if hasEncryptionDataAppendedInInputString = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool hasEncryptionDataAppendedInInputString = true,
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

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
                byte[] decryptedData = new byte[(hasEncryptionDataAppendedInInputString ? encryptedStringBytesWithEncryptionData.Length : encryptedStringBytes.Length)];

                using (var aesGcm = new AesGcm(derivedKey))
                {
                    aesGcm.Decrypt(nonce, (hasEncryptionDataAppendedInInputString ? encryptedStringBytesWithEncryptionData : encryptedStringBytes), tag, decryptedData, associatedData);
                }

                return new AesDecryptionResult()
                {
                    Success = true,
                    Message = MessageDictionary.Instance["Decryption.DecryptSuccess"],
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
                    Message = $"{MessageDictionary.Instance["Decryption.ExceptionError"]}\n{ex.ToString()}"
                };
            }
        }

#endregion string decryption

#endregion public methods
    }
}
#endif