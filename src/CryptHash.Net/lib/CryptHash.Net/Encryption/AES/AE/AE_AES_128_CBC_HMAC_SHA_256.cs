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
using CryptHash.Net.Util;

namespace CryptHash.Net.Encryption.AES.AE
{
    public class AE_AES_128_CBC_HMAC_SHA_256 : AesBase
    {
        #region fields

        private static readonly int _keyBitSize = 128;
        private static readonly int _keyBytesLength = (_keyBitSize / 8);

        private static readonly int _IVBitSize = 128;
        private static readonly int _IVBytesLength = (_IVBitSize / 8);

        private static readonly int _saltBitSize = 128;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

        private static readonly int _tagBitSize = 128;
        private static readonly int _tagBytesLength = (_tagBitSize / 8);

        private static readonly int _iterationsForPBKDF2 = 100000;

        private static readonly CipherMode _cipherMode = CipherMode.CBC;
        private static readonly PaddingMode _paddingMode = PaddingMode.PKCS7;

        #endregion fields


        #region constructors

        public AE_AES_128_CBC_HMAC_SHA_256() : base() { }

        public AE_AES_128_CBC_HMAC_SHA_256(byte[] key, byte[] IV)
            : base(key, IV, _cipherMode, _paddingMode) { }

        #endregion constructors


        #region public methods


        #region string encryption

        public AesEncryptionResult EncryptString(string plainString, string password, bool appendEncryptionDataToOutputString = true)
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

            return EncryptString(plainStringBytes, passwordBytes, appendEncryptionDataToOutputString);
        }

        public AesEncryptionResult EncryptString(string plainString, SecureString secStrPassword, bool appendEncryptionDataToOutputString = true)
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

            return EncryptString(plainStringBytes, passwordBytes, appendEncryptionDataToOutputString);
        }

        public AesEncryptionResult EncryptString(byte[] plainStringBytes, SecureString secStrPassword, bool appendEncryptionDataToOutputString = true)
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

            return EncryptString(plainStringBytes, passwordBytes, appendEncryptionDataToOutputString);
        }

        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes, bool appendEncryptionDataToOutputString = true)
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
                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForPBKDF2);
                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();

                var aesEncryptionResult = base.EncryptWithMemoryStream(plainStringBytes, cryptKey, null, _cipherMode, _paddingMode);

                if (aesEncryptionResult.Success)
                {
                    byte[] tag;
                    byte[] hmacSha256;

                    if (appendEncryptionDataToOutputString)
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
                                hmacSha256 = CommonMethods.ComputeHMACSHA256HashFromDataBytes(authKey, encryptedData, 0, encryptedData.Length);
                                tag = hmacSha256.Take(_tagBytesLength).ToArray();
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
                        hmacSha256 = CommonMethods.ComputeHMACSHA256HashFromDataBytes(authKey, aesEncryptionResult.EncryptedDataBytes, 0, aesEncryptionResult.EncryptedDataBytes.Length);
                        tag = hmacSha256.Take(_tagBytesLength).ToArray();

                        aesEncryptionResult.Salt = salt;
                        aesEncryptionResult.Tag = tag;
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

        #endregion string encryption


        #region string decryption

        public AesDecryptionResult DecryptString(string base64EncryptedString, string password, bool hasEncryptionDataAppendedInInputString = true)
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

            return DecryptString(encryptedStringBytes, passwordBytes, hasEncryptionDataAppendedInInputString);
        }

        public AesDecryptionResult DecryptString(string base64EncryptedString, SecureString secStrPassword, bool hasEncryptionDataAppendedInInputString = true)
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

            return DecryptString(encryptedStringBytes, passwordBytes, hasEncryptionDataAppendedInInputString);
        }

        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, bool hasEncryptionDataAppendedInInputString = true)
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

            return DecryptString(encryptedStringBytes, passwordBytes, hasEncryptionDataAppendedInInputString);
        }

        public AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes,
            bool hasEncryptionDataAppendedInInputString = true, byte[] sentTag = null,
            byte[] salt = null, byte[] IV = null)
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

            if (hasEncryptionDataAppendedInInputString)
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
                if (hasEncryptionDataAppendedInInputString)
                {
                    sentTag = new byte[_tagBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength), sentTag, 0, sentTag.Length);

                    salt = new byte[_saltBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength), salt, 0, salt.Length);

                    IV = new byte[_IVBytesLength];
                    Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _IVBytesLength), IV, 0, IV.Length);
                }

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForPBKDF2);
                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();
                var hmacSha256 = CommonMethods.ComputeHMACSHA256HashFromDataBytes(authKey, encryptedStringBytes, 0, (hasEncryptionDataAppendedInInputString ? (encryptedStringBytes.Length - _tagBytesLength) : encryptedStringBytes.Length));
                var calcTag = hmacSha256.Take(_tagBytesLength).ToArray();

                if (!CommonMethods.TagsMatch(calcTag, sentTag))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = MessageDictionary.Instance["Decryption.AuthenticationTagsMismatchError"]
                    };
                }

                byte[] encryptedSourceDataStringBytes = null;

                if (hasEncryptionDataAppendedInInputString)
                {
                    encryptedSourceDataStringBytes = new byte[(encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _IVBytesLength)];
                    Array.Copy(encryptedStringBytes, 0, encryptedSourceDataStringBytes, 0, encryptedSourceDataStringBytes.Length);
                }

                var aesDecryptionResult = base.DecryptWithMemoryStream((hasEncryptionDataAppendedInInputString ? encryptedSourceDataStringBytes : encryptedStringBytes),
                    cryptKey, IV, _cipherMode, _paddingMode);

                if (aesDecryptionResult.Success)
                {
                    aesDecryptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecryptionResult.DecryptedDataBytes);
                    aesDecryptionResult.Salt = salt;
                    aesDecryptionResult.Tag = sentTag;
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
                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForPBKDF2);

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

                    var hmacSha256 = CommonMethods.ComputeHMACSHA256HashFromFile(encryptedFilePath, authKey);
                    var tag = hmacSha256.Take(_tagBytesLength).ToArray();

                    if (appendEncryptionDataToOutputFile)
                    {
                        CommonMethods.AppendDataBytesToFile(encryptedFilePath, tag);
                        RaiseOnEncryptionMessage(MessageDictionary.Instance["Encryption.FileAdditionalDataWritten"]);
                    }

                    aesEncryptionResult.Salt = salt;
                    aesEncryptionResult.Tag = tag;
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

        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, string password, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true)
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

            return DecryptFile(encryptedFilePath, decryptedFilePath, passwordBytes, deleteSourceFile, hasEncryptionDataAppendedInInputFile);
        }

        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, SecureString secStrPassword, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true)
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

            return DecryptFile(encryptedFilePath, decryptedFilePath, passwordBytes, deleteSourceFile, hasEncryptionDataAppendedInInputFile);
        }

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

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, (_keyBytesLength * 2), _iterationsForPBKDF2);
                byte[] cryptKey = derivedKey.Take(_keyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(_keyBytesLength).Take(_keyBytesLength).ToArray();

                var hmacSha256 = CommonMethods.ComputeHMACSHA256HashFromFile(encryptedFilePath, authKey, 0, (hasEncryptionDataAppendedInInputFile ? encryptedFileSize - _tagBytesLength : encryptedFileSize));
                var calcTag = hmacSha256.Take(_tagBytesLength).ToArray();

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
