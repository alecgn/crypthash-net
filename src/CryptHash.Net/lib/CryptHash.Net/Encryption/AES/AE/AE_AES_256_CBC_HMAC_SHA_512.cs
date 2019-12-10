/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using CryptHash.Net.Encryption.AES.Base;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Hash;
using CryptHash.Net.Hash.Enums;
using CryptHash.Net.Util;

namespace CryptHash.Net.Encryption.AES.AE
{
    public class AE_AES_256_CBC_HMAC_SHA_512 : AesBase
    {
        #region fields

        private static readonly int _keyBitSize = 256;
        private static readonly int _keyBytesLength = (_keyBitSize / 8);

        private static readonly int _blockBitSize = 128;
        private static readonly int _blockBytesLength = (_blockBitSize / 8);

        private static readonly int _IVBitSize = 128;
        private static readonly int _IVBytesLength = (_IVBitSize / 8);

        private static readonly int _saltBitSize = 128;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

        private static readonly int _tagBitSize = 256;
        private static readonly int _tagBytesLength = (_tagBitSize / 8);

        private static readonly int _iterationsForKeyDerivationFunction = 100000;

        private static readonly CipherMode _cipherMode = CipherMode.CBC;
        private static readonly PaddingMode _paddingMode = PaddingMode.PKCS7;

        #endregion fields


        #region constructors

        public AE_AES_256_CBC_HMAC_SHA_512() : base() { }

        public AE_AES_256_CBC_HMAC_SHA_512(byte[] key, byte[] IV)
            : base(key, IV) { }

        #endregion constructors


        #region public methods


        #region string encryption

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password string.
        /// </summary>
        /// <param name="plainString">The input plain string to encrypt.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(string plainString, string password, bool appendEncryptionDataToOutput = true)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            var plainStringBytes = Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return EncryptString(plainStringBytes, passwordBytes, appendEncryptionDataToOutput);
        }

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="plainString">The input plain string to encrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(string plainString, SecureString secStrPassword, bool appendEncryptionDataToOutput = true)
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

            return EncryptString(plainStringBytes, passwordBytes, appendEncryptionDataToOutput);
        }

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(byte[] plainStringBytes, SecureString secStrPassword, bool appendEncryptionDataToOutput = true)
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

            return EncryptString(plainStringBytes, passwordBytes, appendEncryptionDataToOutput);
        }

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes, bool appendEncryptionDataToOutput = true)
        {
            if (plainStringBytes == null || plainStringBytes.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            if (passwordBytes == null || passwordBytes.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            try
            {
                //byte[] salt = CommonMethods.GenerateRandomBytes(_saltBytesLength);
                byte[] salt = CommonMethods.GenerateSalt();
                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForKeyDerivationFunction);
                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();

                var aesEncryptionResult = base.EncryptWithMemoryStream(plainStringBytes, cryptKey, null, _cipherMode, _paddingMode);

                if (aesEncryptionResult.Success)
                {
                    byte[] tag;
                    byte[] hmacSha512bytes;

                    if (appendEncryptionDataToOutput)
                    {
                        using (var ms = new MemoryStream())
                        {
                            using (var bw = new BinaryWriter(ms))
                            {
                                bw.Write(aesEncryptionResult.EncryptedDataBytes);
                                bw.Write(aesEncryptionResult.IV);
                                bw.Write(salt);
                                bw.Flush();
                                var encryptedData = ms.ToArray();
                                //hmacSha512bytes = CommonMethods.ComputeHMACSHA512HashFromDataBytes(authKey, encryptedData, 0, encryptedData.Length);
                                hmacSha512bytes = new HMAC_SHA_512().ComputeHMAC(encryptedData, authKey, 0, encryptedData.Length).HashBytes;
                                tag = hmacSha512bytes.Take(_tagBytesLength).ToArray();
                                bw.Write(tag);
                            }

                            aesEncryptionResult.EncryptedDataBytes = ms.ToArray();
                            aesEncryptionResult.EncryptedDataBase64String = Convert.ToBase64String(aesEncryptionResult.EncryptedDataBytes);
                            aesEncryptionResult.Salt = salt;
                            aesEncryptionResult.Tag = tag;
                        }
                    }
                    else
                    {
                        //hmacSha512bytes = CommonMethods.ComputeHMACSHA512HashFromDataBytes(authKey, aesEncryptionResult.EncryptedDataBytes, 0, aesEncryptionResult.EncryptedDataBytes.Length);
                        hmacSha512bytes = new HMAC_SHA_512().ComputeHMAC(aesEncryptionResult.EncryptedDataBytes, authKey, 0, aesEncryptionResult.EncryptedDataBytes.Length).HashBytes;
                        tag = hmacSha512bytes.Take(_tagBytesLength).ToArray();

                        aesEncryptionResult.Salt = salt;
                        aesEncryptionResult.Tag = tag;
                        aesEncryptionResult.AuthenticationKey = authKey;
                    }
                }

                return aesEncryptionResult;
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

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="encryptionKey">The byte array of the 256 bit encryption key used to encrypt data. Leave empty or pass null to auto-generate a secure random 256 bit key.</param>
        /// <param name="IV">The byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null to auto-generate a secure random 128 bit IV.</param>
        /// <param name="authenticationKey">The byte array of the authentication key used to generate a tag and authenticate the data during decryption. Leave empty or pass null to auto-generate a secure random 256 bit authentication key.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] encryptionKey = null, byte[] IV = null, byte[] authenticationKey = null)
        {
            if (plainStringBytes == null || plainStringBytes.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.InputRequired"]
                };
            }

            try
            {
                encryptionKey = encryptionKey ?? CommonMethods.GenerateRandomBytes(_keyBytesLength);
                IV = IV ?? CommonMethods.GenerateRandomBytes(_blockBytesLength);
                authenticationKey = authenticationKey ?? CommonMethods.GenerateRandomBytes(_tagBytesLength);

                var aesEncryptionResult = base.EncryptWithMemoryStream(plainStringBytes, encryptionKey, IV, _cipherMode, _paddingMode);

                if (aesEncryptionResult.Success)
                {
                    byte[] tag;
                    byte[] hmacSha512HashedBytes;

                    //hmacSha256 = CommonMethods.ComputeHMACSHA256HashFromDataBytes(authKey, aesEncryptionResult.EncryptedDataBytes, 0, aesEncryptionResult.EncryptedDataBytes.Length);
                    hmacSha512HashedBytes = new HMAC_SHA_512().ComputeHMAC(aesEncryptionResult.EncryptedDataBytes, authenticationKey, 0, aesEncryptionResult.EncryptedDataBytes.Length).HashBytes;
                    tag = hmacSha512HashedBytes.Take(_tagBytesLength).ToArray();
                    aesEncryptionResult.Tag = tag;
                    aesEncryptionResult.AuthenticationKey = authenticationKey;
                }

                return aesEncryptionResult;
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
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password string.
        /// </summary>
        /// <param name="base64EncryptedString">The base64 encoded input string to decrypt.</param>
        /// <param name="password">The password string where the decryption key will be derived from.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesDecryptionResult</returns>
        public AesDecryptionResult DecryptString(string base64EncryptedString, string password, bool hasEncryptionDataAppendedInInput = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
        {
            if (string.IsNullOrWhiteSpace(base64EncryptedString))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var encryptedStringBytes = Convert.FromBase64String(base64EncryptedString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return DecryptString(encryptedStringBytes, passwordBytes, hasEncryptionDataAppendedInInput, sentTag, salt, IV);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password in a SecureString.
        /// </summary>
        /// <param name="base64EncryptedString">The base64 encoded input string to decrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the decryption key will be derived from.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesDecryptionResult</returns>
        public AesDecryptionResult DecryptString(string base64EncryptedString, SecureString secStrPassword, bool hasEncryptionDataAppendedInInput = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
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

            var encryptedStringBytes = Convert.FromBase64String(base64EncryptedString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);

            return DecryptString(encryptedStringBytes, passwordBytes, hasEncryptionDataAppendedInInput, sentTag, salt, IV);
        }

        /// <summary>
        /// Decrypts a byte array of the string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password in a SecureString.
        /// </summary>
        /// <param name="encryptedStringBytes">The input byte array of the string to decrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the decryption key will be derived from.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input byte array of the encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesDecryptionResult</returns>
        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, bool hasEncryptionDataAppendedInInput = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
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

            return DecryptString(encryptedStringBytes, passwordBytes, hasEncryptionDataAppendedInInput, sentTag, salt, IV);
        }

        /// <summary>
        /// Decrypts a byte array of the string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="encryptedStringBytes">The input byte array of the string to decrypt.</param>
        /// <param name="passwordBytes">The byte array of the password where the decryption key will be derived from.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input byte array of the encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesDecryptionResult</returns>
        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes, bool hasEncryptionDataAppendedInInput = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            if (passwordBytes == null || passwordBytes.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            if (hasEncryptionDataAppendedInInput)
            {
                if (encryptedStringBytes.Length < (_tagBytesLength + _saltBytesLength + _IVBytesLength))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = MessageDictionary.Instance["Common.IncorrectInputLengthError"]
                    };
                }
            }

            try
            {
                if (hasEncryptionDataAppendedInInput)
                {
                    sentTag = new byte[_tagBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength), sentTag, 0, sentTag.Length);

                    salt = new byte[_saltBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength), salt, 0, salt.Length);

                    IV = new byte[_IVBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _IVBytesLength), IV, 0, IV.Length);
                }

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForKeyDerivationFunction);
                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();
                //var hmacSha512 = CommonMethods.ComputeHMACSHA512HashFromDataBytes(authKey, encryptedStringBytes, 0, (hasEncryptionDataAppendedInInput ? (encryptedStringBytes.Length - _tagBytesLength) : encryptedStringBytes.Length));
                var hmacSha512 = new HMAC_SHA_512().ComputeHMAC(encryptedStringBytes, authKey, 0, (hasEncryptionDataAppendedInInput ? (encryptedStringBytes.Length - _tagBytesLength) : encryptedStringBytes.Length)).HashBytes;
                var calcTag = hmacSha512.Take(_tagBytesLength).ToArray();

                if (!CommonMethods.TagsMatch(calcTag, sentTag))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = MessageDictionary.Instance["Decryption.AuthenticationTagsMismatchError"]
                    };
                }

                byte[] encryptedSourceDataStringBytes = null;

                if (hasEncryptionDataAppendedInInput)
                {
                    encryptedSourceDataStringBytes = new byte[(encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _IVBytesLength)];
                    Array.Copy(encryptedStringBytes, 0, encryptedSourceDataStringBytes, 0, encryptedSourceDataStringBytes.Length);
                }

                var aesDecryptionResult = base.DecryptWithMemoryStream((hasEncryptionDataAppendedInInput ? encryptedSourceDataStringBytes : encryptedStringBytes),
                    cryptKey, IV, _cipherMode, _paddingMode);

                if (aesDecryptionResult.Success)
                {
                    aesDecryptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecryptionResult.DecryptedDataBytes);
                    aesDecryptionResult.Salt = salt;
                    aesDecryptionResult.Tag = sentTag;
                    aesDecryptionResult.AuthenticationKey = authKey;
                }

                return aesDecryptionResult;
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

        /// <summary>
        /// Decrypts a byte array of the string using AES with a 256 bits key in CBC mode with HMACSHA512 authentication.
        /// </summary>
        /// <param name="encryptedStringBytes">The input byte array of the string to decrypt.</param>
        /// <param name="encryptionKey">The previously generated byte array of the 256 bit encryption key used to encrypt data.</param>
        /// <param name="IV">The previously generated byte array of the 128 bit Initialization Vector used to initialize the first block.</param>
        /// <param name="authenticationKey">The previously generated byte array of the 256 bit authentication key.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag used to authenticate the data.</param>
        /// <returns>AesDecryptionResult</returns>
        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] encryptionKey, byte[] IV, byte[] authenticationKey, byte[] sentTag)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.InputRequired"]
                };
            }

            try
            {
                var hmacSha512Bytes = new HMAC_SHA_512().ComputeHMAC(encryptedStringBytes, authenticationKey, 0, encryptedStringBytes.Length).HashBytes;
                var calcTag = hmacSha512Bytes.Take(_tagBytesLength).ToArray();

                if (!CommonMethods.TagsMatch(calcTag, sentTag))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = MessageDictionary.Instance["Decryption.AuthenticationTagsMismatchError"]
                    };
                }

                var aesDecryptionResult = base.DecryptWithMemoryStream(encryptedStringBytes, encryptionKey, IV, _cipherMode, _paddingMode);

                if (aesDecryptionResult.Success)
                {
                    aesDecryptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecryptionResult.DecryptedDataBytes);
                    aesDecryptionResult.Tag = sentTag;
                    aesDecryptionResult.AuthenticationKey = authenticationKey;
                }

                return aesDecryptionResult;
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


        #region file encryption

        /// <summary>
        /// Encrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password string.
        /// </summary>
        /// <param name="sourceFilePath">The input source file path to encrypt.</param>
        /// <param name="encryptedFilePath">The output file path to save the encrypted file. Pass null or an empty string to not generate a new file, encrypting only the input source file and mantaining its path.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after encryption or not.</param>
        /// <param name="appendEncryptionDataToOutputFile">Flag to indicate if the encryption additional data required to decrypt will be appended to the output file. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, string password, bool deleteSourceFile = false, bool appendEncryptionDataToOutputFile = true)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return EncryptFile(sourceFilePath, encryptedFilePath, passwordBytes, deleteSourceFile, appendEncryptionDataToOutputFile);
        }

        /// <summary>
        /// Encrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="sourceFilePath">The input source file path to encrypt.</param>
        /// <param name="encryptedFilePath">The output file path to save the encrypted file. Pass null or an empty string to not generate a new file, encrypting only the input source file and mantaining its path.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after encryption or not.</param>
        /// <param name="appendEncryptionDataToOutputFile">Flag to indicate if the encryption additional data required to decrypt will be appended to the output file. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, SecureString secStrPassword, bool deleteSourceFile = false, bool appendEncryptionDataToOutputFile = true)
        {
            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);

            return EncryptFile(sourceFilePath, encryptedFilePath, passwordBytes, deleteSourceFile, appendEncryptionDataToOutputFile);
        }

        /// <summary>
        /// Encrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="sourceFilePath">The input source file path to encrypt.</param>
        /// <param name="encryptedFilePath">The output file path to save the encrypted file. Pass null or an empty string to not generate a new file, encrypting only the input source file and mantaining its path.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after encryption or not.</param>
        /// <param name="appendEncryptionDataToOutputFile">Flag to indicate if the encryption additional data required to decrypt will be appended to the output file. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false, bool appendEncryptionDataToOutputFile = true)
        {
            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                encryptedFilePath = sourceFilePath;
            }

            if (passwordBytes == null || passwordBytes.Length <= 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Encryption.PasswordRequired"]
                };
            }

            try
            {
                //byte[] salt = CommonMethods.GenerateRandomBytes(_saltBytesLength);
                byte[] salt = CommonMethods.GenerateSalt();
                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForKeyDerivationFunction);

                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();

                var aesEncryptionResult = base.EncryptWithFileStream(sourceFilePath, encryptedFilePath, cryptKey, null, _cipherMode, _paddingMode, deleteSourceFile);

                if (aesEncryptionResult.Success)
                {
                    if (appendEncryptionDataToOutputFile)
                    {
                        RaiseOnEncryptionMessage(MessageDictionary.Instance["Encryption.FileAdditionalDataWriting"]);
                        byte[] additionalData = new byte[_IVBytesLength + _saltBytesLength];

                        Array.Copy(aesEncryptionResult.IV, 0, additionalData, 0, _IVBytesLength);
                        Array.Copy(salt, 0, additionalData, _IVBytesLength, _saltBytesLength);

                        CommonMethods.AppendDataBytesToFile(encryptedFilePath, additionalData);
                    }

                    //var hmacSha512 = CommonMethods.ComputeHMACSHA512HashFromFile(encryptedFilePath, authKey);
                    var hmacSha512 = new HMAC_SHA_512().ComputeFileHMAC(encryptedFilePath, authKey).HashBytes;
                    var tag = hmacSha512.Take(_tagBytesLength).ToArray();

                    if (appendEncryptionDataToOutputFile)
                    {
                        CommonMethods.AppendDataBytesToFile(encryptedFilePath, tag);
                        RaiseOnEncryptionMessage(MessageDictionary.Instance["Encryption.FileAdditionalDataWritten"]);
                    }

                    aesEncryptionResult.Salt = salt;
                    aesEncryptionResult.Tag = tag;
                    aesEncryptionResult.AuthenticationKey = authKey;
                }

                return aesEncryptionResult;
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

        #endregion file encryption


        #region file decryption

        /// <summary>
        /// Decrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password string.
        /// </summary>
        /// <param name="encryptedFilePath">The input source encrypted file path do decrypt.</param>
        /// <param name="decryptedFilePath">The output file path to save the decrypted file. Pass null or an empty string to not generate a new file, decrypting only the input source encrypted file and mantaining its path.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after decryption or not.</param>
        /// <param name="hasEncryptionDataAppendedInInputFile">Flag to indicate if the encryption additional data required to decrypt is present in the input source encrypted file. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, string password, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return DecryptFile(encryptedFilePath, decryptedFilePath, passwordBytes, deleteSourceFile, hasEncryptionDataAppendedInInputFile, sentTag, salt, IV);
        }

        /// <summary>
        /// Decrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="encryptedFilePath">The input source encrypted file path do decrypt.</param>
        /// <param name="decryptedFilePath">The output file path to save the decrypted file. Pass null or an empty string to not generate a new file, decrypting only the input source encrypted file and mantaining its path.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after decryption or not.</param>
        /// <param name="hasEncryptionDataAppendedInInputFile">Flag to indicate if the encryption additional data required to decrypt is present in the input source encrypted file. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, SecureString secStrPassword, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
        {
            if (secStrPassword == null || secStrPassword.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);

            return DecryptFile(encryptedFilePath, decryptedFilePath, passwordBytes, deleteSourceFile, hasEncryptionDataAppendedInInputFile, sentTag, salt, IV);
        }

        /// <summary>
        /// Decrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="encryptedFilePath">The input source encrypted file path do decrypt.</param>
        /// <param name="decryptedFilePath">The output file path to save the decrypted file. Pass null or an empty string to not generate a new file, decrypting only the input source encrypted file and mantaining its path.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after decryption or not.</param>
        /// <param name="hasEncryptionDataAppendedInInputFile">Flag to indicate if the encryption additional data required to decrypt is present in the input source encrypted file. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="IV">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true,
            byte[] sentTag = null, byte[] salt = null, byte[] IV = null)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Decryption.EncryptedFileNotFound"]}: \"{encryptedFilePath}\"."
                };
            }

            if (string.IsNullOrWhiteSpace(decryptedFilePath))
            {
                decryptedFilePath = encryptedFilePath;
            }

            if (passwordBytes == null || passwordBytes.Length <= 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Decryption.PasswordRequired"]
                };
            }

            var encryptedFileSize = new FileInfo(encryptedFilePath).Length;

            if (hasEncryptionDataAppendedInInputFile)
            {
                if (encryptedFileSize < (_tagBytesLength + _saltBytesLength + _IVBytesLength))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = MessageDictionary.Instance["Common.IncorrectInputLengthError"]
                    };
                }
            }

            try
            {
                if (hasEncryptionDataAppendedInInputFile)
                {
                    byte[] additionalData = new byte[_IVBytesLength + _saltBytesLength + _tagBytesLength];
                    additionalData = CommonMethods.GetBytesFromFile(encryptedFilePath, additionalData.Length, (encryptedFileSize - additionalData.Length));

                    IV = new byte[_IVBytesLength];
                    salt = new byte[_saltBytesLength];
                    sentTag = new byte[_tagBytesLength];

                    Array.Copy(additionalData, 0, IV, 0, _IVBytesLength);
                    Array.Copy(additionalData, _IVBytesLength, salt, 0, _saltBytesLength);
                    Array.Copy(additionalData, (_IVBytesLength + _saltBytesLength), sentTag, 0, _tagBytesLength);
                }

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForKeyDerivationFunction);
                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();

                //var hmacSha512 = CommonMethods.ComputeHMACSHA512HashFromFile(encryptedFilePath, authKey, 0, (hasEncryptionDataAppendedInInputFile ? encryptedFileSize - _tagBytesLength : encryptedFileSize));
                var hmacSha512 = new HMAC_SHA_512().ComputeFileHMAC(encryptedFilePath, authKey, 0, (hasEncryptionDataAppendedInInputFile ? encryptedFileSize - _tagBytesLength : encryptedFileSize)).HashBytes;
                var calcTag = hmacSha512.Take(_tagBytesLength).ToArray();

                if (!CommonMethods.TagsMatch(calcTag, sentTag))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = MessageDictionary.Instance["Decryption.AuthenticationTagsMismatchError"]
                    };
                }

                long endPosition = (hasEncryptionDataAppendedInInputFile ? (encryptedFileSize - _tagBytesLength - _saltBytesLength - _IVBytesLength) : encryptedFileSize);

                var aesDecryptionResult = base.DecryptWithFileStream(encryptedFilePath, decryptedFilePath, cryptKey, IV, _cipherMode, _paddingMode, deleteSourceFile, 4, 0, endPosition);

                if (aesDecryptionResult.Success)
                {
                    aesDecryptionResult.Salt = salt;
                    aesDecryptionResult.Tag = sentTag;
                    aesDecryptionResult.AuthenticationKey = authKey;
                }

                return aesDecryptionResult;
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

        #endregion file decryption


        #endregion public methods
    }
}
