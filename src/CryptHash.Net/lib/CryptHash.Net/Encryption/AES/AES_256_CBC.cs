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

        public AesEncryptionResult EncryptString(string stringToEncrypt, string password)
        {
            if (string.IsNullOrWhiteSpace(stringToEncrypt))
            {
                throw new ArgumentException("String to encrypt required.", nameof(stringToEncrypt));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password required.", nameof(password));
            }

            try
            {
                var stringToEncryptBytes = Encoding.UTF8.GetBytes(stringToEncrypt);
                var passwordBytes = Encoding.UTF8.GetBytes(password);

                return EncryptString(stringToEncryptBytes, passwordBytes);
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    EncryptedDataBytes = null,
                    EncryptedDataString = null
                };
            }
        }

        public AesEncryptionResult EncryptString(string stringToEncrypt, SecureString secStrPassword)
        {
            if (string.IsNullOrWhiteSpace(stringToEncrypt))
            {
                throw new ArgumentException("String to encrypt required.", nameof(stringToEncrypt));
            }

            if (secStrPassword.Length <= 0)
            {
                throw new ArgumentException("SecureString length cannot be less or equal zero.", nameof(secStrPassword));
            }

            byte[] passwordBytes = null;

            try
            {
                var stringToEncryptBytes = Encoding.UTF8.GetBytes(stringToEncrypt);

                //using (secStrPassword)
                //{
                    passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
                //}

                return EncryptString(stringToEncryptBytes, passwordBytes);
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    EncryptedDataBytes = null,
                    EncryptedDataString = null
                };
            }
            finally
            {
                if (passwordBytes != null)
                {
                    Array.Clear(passwordBytes, 0, passwordBytes.Length);
                    passwordBytes = null;
                }
            }
        }

        public AesEncryptionResult EncryptString(byte[] stringToEncryptBytes, byte[] passwordBytes)
        {
            if (stringToEncryptBytes == null || stringToEncryptBytes.Length == 0)
            {
                throw new ArgumentException("String to encrypt required.", nameof(stringToEncryptBytes));
            }

            if (passwordBytes == null || passwordBytes.Length == 0)
            {
                throw new ArgumentException("Password required.", nameof(passwordBytes));
            }

            try
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
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    EncryptedDataBytes = null,
                    EncryptedDataString = null
                };
            }
        }

        public AesEncryptionResult DecryptString(string stringToDecrypt, string password)
        {
            if (string.IsNullOrWhiteSpace(stringToDecrypt))
            {
                throw new ArgumentException("String to decrypt required.", nameof(stringToDecrypt));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password required.", nameof(password));
            }

            try
            {
                var stringToDecryptBytes = Encoding.UTF8.GetBytes(stringToDecrypt);
                var passwordBytes = Encoding.UTF8.GetBytes(password);

                return DecryptString(stringToDecryptBytes, passwordBytes);
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    DecryptedDataBytes = null,
                    DecryptedDataString = null
                };
            }
        }

        public AesEncryptionResult DecryptString(string stringToDecrypt, SecureString secStrPassword)
        {
            if (string.IsNullOrWhiteSpace(stringToDecrypt))
            {
                throw new ArgumentException("String to decrypt required.", nameof(stringToDecrypt));
            }

            if (secStrPassword.Length <= 0)
            {
                throw new ArgumentException("SecureString length cannot be less or equal zero.", nameof(secStrPassword));
            }

            byte[] passwordBytes = null;

            try
            {
                var stringToDecryptBytes = Convert.FromBase64String(stringToDecrypt);

                //using (secStrPassword)
                //{
                    passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
                //}

                return DecryptString(stringToDecryptBytes, passwordBytes);
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    DecryptedDataBytes = null,
                    DecryptedDataString = null
                };
            }
            finally
            {
                if (passwordBytes != null)
                {
                    Array.Clear(passwordBytes, 0, passwordBytes.Length);
                    passwordBytes = null;
                }
            }
        }

        public AesEncryptionResult DecryptString(byte[] stringToDecryptBytes, byte[] passwordBytes)
        {
            if (stringToDecryptBytes == null || stringToDecryptBytes.Length == 0)
            {
                throw new ArgumentException("String to decrypt required.", nameof(stringToDecryptBytes));
            }

            if (passwordBytes == null || passwordBytes.Length == 0)
            {
                throw new ArgumentException("Password required.", nameof(stringToDecryptBytes));
            }

            try
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
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    DecryptedDataBytes = null,
                    DecryptedDataString = null
                };
            }
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
