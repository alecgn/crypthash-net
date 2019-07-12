/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.Base;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.Utils;
using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CryptHash.Net.Encryption.AES.AE
{
    public class AE_AES_256_CBC_HMAC_SHA_256 : AesBase
    {
        #region fields

        private static readonly int _blockBitSize = 128;
        private static readonly int _blockBytesLength = (_blockBitSize / 8);

        private static readonly int _IVBitSize = 128;
        private static readonly int _IVBytesLength = (_IVBitSize / 8);

        private static readonly int _keyBitSize = 256;
        private static readonly int _keyBytesLength = (_keyBitSize / 8);

        private static readonly int _saltBitSize = 256;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

        private static readonly int _tagBitSize = 256;
        private static readonly int _tagBytesLength = (_tagBitSize / 8);

        private static readonly int _iterationsForPBKDF2 = 100000;

        private static readonly CipherMode _cipherMode = CipherMode.CBC;
        private static readonly PaddingMode _paddingMode = PaddingMode.PKCS7;

        #endregion fields


        #region constructors

        public AE_AES_256_CBC_HMAC_SHA_256() : base() { }

        public AE_AES_256_CBC_HMAC_SHA_256(byte[] key, byte[] IV)
            : base(key, IV, _cipherMode, _paddingMode) { }

        #endregion constructors


        #region public methods

        public AesEncryptionResult EncryptString(string plainString, string password)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var plainStringBytes = Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return EncryptString(plainStringBytes, passwordBytes);
        }

        public AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes)
        {
            if (plainStringBytes == null || plainStringBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (passwordBytes == null || passwordBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            try
            {
                byte[] cryptSalt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);
                byte[] authSalt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);

                // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
                byte[] cryptKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, cryptSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);
                byte[] authKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, authSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

                var aesEncryptionResult = base.EncryptWithMemoryStream(plainStringBytes, cryptKey, null, _cipherMode, _paddingMode);

                if (aesEncryptionResult.Success)
                {
                    using (var ms = new MemoryStream())
                    {
                        byte[] tag;

                        using (var bw = new BinaryWriter(ms))
                        {
                            bw.Write(aesEncryptionResult.EncryptedDataBytes);
                            bw.Write(aesEncryptionResult.IV);
                            bw.Write(cryptSalt);
                            bw.Write(authSalt);
                            bw.Flush();
                            var encryptedData = ms.ToArray();
                            tag = EncryptionUtils.ComputeHMACSHA256HashFromDataBytes(authKey, encryptedData, 0, encryptedData.Length);
                            bw.Write(tag);
                        }

                        aesEncryptionResult.EncryptedDataBytes = ms.ToArray();
                        aesEncryptionResult.EncryptedDataBase64String = Convert.ToBase64String(aesEncryptionResult.EncryptedDataBytes);
                        aesEncryptionResult.CryptSalt = cryptSalt;
                        aesEncryptionResult.AuthSalt = authSalt;
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
                    Message = $"Error while trying to encrypt string:\n{ex.ToString()}"
                };
            }
        }

        public AesEncryptionResult DecryptString(string base64EncryptedString, string password)
        {
            if (string.IsNullOrWhiteSpace(base64EncryptedString))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to encrypt required."
                };
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var encryptedStringBytes = Convert.FromBase64String(base64EncryptedString);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return DecryptString(encryptedStringBytes, passwordBytes);
        }

        public AesEncryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "String to decrypt required."
                };
            }

            if (passwordBytes == null || passwordBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            if (encryptedStringBytes.Length < (_tagBytesLength + (_saltBytesLength * 2) + _IVBytesLength))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Incorrect data length, string data tampered."
                };
            }

            try
            {
                var sentTag = new byte[_tagBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength), sentTag, 0, sentTag.Length);

                byte[] authSalt = new byte[_saltBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength), authSalt, 0, authSalt.Length);

                byte[] cryptSalt = new byte[_saltBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - (_saltBytesLength * 2)), cryptSalt, 0, cryptSalt.Length);

                byte[] IV = new byte[_IVBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - (_saltBytesLength * 2) - _IVBytesLength), IV, 0, IV.Length);

                // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
                byte[] cryptKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, cryptSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

                // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
                byte[] authKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, authSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

                var calcTag = EncryptionUtils.ComputeHMACSHA256HashFromDataBytes(authKey, encryptedStringBytes, 0, (encryptedStringBytes.Length - _tagBytesLength));

                if (!EncryptionUtils.TagsMatch(calcTag, sentTag))
                {
                    return new AesEncryptionResult()
                    {
                        Success = false,
                        Message = "Authentication for string decryption failed, wrong password or data tampered."
                    };
                }

                byte[] encryptedSourceDataStringBytes = new byte[(encryptedStringBytes.Length - (_saltBytesLength * 2) - _IVBytesLength - _tagBytesLength)];
                Array.Copy(encryptedStringBytes, 0, encryptedSourceDataStringBytes, 0, encryptedSourceDataStringBytes.Length);

                var aesDecriptionResult = base.DecryptWithMemoryStream(encryptedSourceDataStringBytes, cryptKey, IV, _cipherMode, _paddingMode);

                if (aesDecriptionResult.Success)
                {
                    aesDecriptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecriptionResult.DecryptedDataBytes);
                    aesDecriptionResult.CryptSalt = cryptSalt;
                    aesDecriptionResult.AuthSalt = authSalt;
                    aesDecriptionResult.Tag = sentTag;
                }

                return aesDecriptionResult;
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to decrypt string:\n{ex.ToString()}"
                };
            }
        }

        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, string password, bool deleteSourceFile = false)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return EncryptFile(sourceFilePath, encryptedFilePath, passwordBytes, deleteSourceFile);
        }

        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false)
        {
            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                encryptedFilePath = sourceFilePath;
            }

            if (passwordBytes == null || passwordBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            try
            {
                byte[] cryptSalt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);
                byte[] authSalt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);

                // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
                byte[] cryptKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, cryptSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);
                byte[] authKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, authSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

                var aesEncryptionResult = base.EncryptWithFileStream(sourceFilePath, encryptedFilePath, cryptKey, null, _cipherMode, _paddingMode, deleteSourceFile);

                if (aesEncryptionResult.Success)
                {
                    RaiseOnEncryptionMessage("Writing additional data to file...");
                    byte[] additionalData = new byte[_IVBytesLength + (_saltBytesLength * 2)];

                    Array.Copy(aesEncryptionResult.IV, 0, additionalData, 0, _IVBytesLength);
                    Array.Copy(cryptSalt, 0, additionalData, _IVBytesLength, _saltBytesLength);
                    Array.Copy(authSalt, 0, additionalData, (_IVBytesLength + _saltBytesLength), _saltBytesLength);

                    EncryptionUtils.AppendDataToFile(encryptedFilePath, additionalData);

                    var tag = EncryptionUtils.ComputeHMACSHA256HashFromFile(encryptedFilePath, authKey);
                    EncryptionUtils.AppendDataToFile(encryptedFilePath, tag);
                    RaiseOnEncryptionMessage("Additional data written to file.");

                    aesEncryptionResult.CryptSalt = cryptSalt;
                    aesEncryptionResult.AuthSalt = authSalt;
                    aesEncryptionResult.Tag = tag;
                }

                return aesEncryptionResult;
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to encrypt file:\n{ex.ToString()}"
                };
            }
        }

        public AesEncryptionResult DecryptFile(string sourceFilePath, string encryptedFilePath, string password, bool deleteSourceFile = false)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return DecryptFile(sourceFilePath, encryptedFilePath, passwordBytes, deleteSourceFile);
        }

        public AesEncryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Encrypted file \"{encryptedFilePath}\" not found."
                };
            }

            if (string.IsNullOrWhiteSpace(decryptedFilePath))
            {
                decryptedFilePath = encryptedFilePath;
            }

            if (passwordBytes == null || passwordBytes.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Password required."
                };
            }

            var encryptedFileSize = new FileInfo(encryptedFilePath).Length;

            if (encryptedFileSize < (_tagBytesLength + (_saltBytesLength * 2) + _IVBytesLength))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Incorrect data length, file data tampered."
                };
            }

            try
            {
                byte[] additionalData = new byte[_IVBytesLength + (_saltBytesLength * 2) + _tagBytesLength];
                additionalData = EncryptionUtils.GetBytesFromFile(encryptedFilePath, additionalData.Length, (encryptedFileSize - additionalData.Length));

                byte[] IV = new byte[_IVBytesLength];
                byte[] cryptSalt = new byte[_saltBytesLength];
                byte[] authSalt = new byte[_saltBytesLength];
                byte[] sentTag = new byte[_tagBytesLength];

                Array.Copy(additionalData, 0, IV, 0, _IVBytesLength);
                Array.Copy(additionalData, _IVBytesLength, cryptSalt, 0, _saltBytesLength);
                Array.Copy(additionalData, (_IVBytesLength + _saltBytesLength), authSalt, 0, _saltBytesLength);
                Array.Copy(additionalData, (_IVBytesLength + (_saltBytesLength * 2)), sentTag, 0, _tagBytesLength);

                var cryptKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, cryptSalt, _keyBytesLength, _iterationsForPBKDF2);
                var authKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, authSalt, _keyBytesLength, _iterationsForPBKDF2);

                var calcTag = EncryptionUtils.ComputeHMACSHA256HashFromFile(encryptedFilePath, authKey, 0, (encryptedFileSize - _tagBytesLength));

                if (!EncryptionUtils.TagsMatch(calcTag, sentTag))
                {
                    return new AesEncryptionResult()
                    {
                        Success = false,
                        Message = "Authentication for file decryption failed, wrong password or data tampered."
                    };
                }

                long endPosition = (encryptedFileSize - _tagBytesLength - (_saltBytesLength * 2) - _IVBytesLength);

                var aesDecryptionResult = base.DecryptWithFileStream(encryptedFilePath, decryptedFilePath, cryptKey, IV, _cipherMode, _paddingMode, deleteSourceFile, 4, 0, endPosition);

                if (aesDecryptionResult.Success)
                {
                    aesDecryptionResult.CryptSalt = cryptSalt;
                    aesDecryptionResult.AuthSalt = authSalt;
                    aesDecryptionResult.Tag = sentTag;
                }

                return aesDecryptionResult;
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to decrypt file:\n{ex.ToString()}"
                };
            }
        }

        #endregion public methods
    }
}
