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
                        using (var bw = new BinaryWriter(ms))
                        {
                            bw.Write(cryptSalt);
                            bw.Write(authSalt);
                            bw.Write(aesEncryptionResult.IVOrNonce);
                            bw.Write(aesEncryptionResult.EncryptedDataBytes);
                            bw.Flush();
                            var encryptedData = ms.ToArray();
                            var tag = EncryptionUtils.CalculateHMACSHA256FromDataBytes(authKey, encryptedData, 0, encryptedData.Length);
                            bw.Write(tag);
                        }

                        aesEncryptionResult.EncryptedDataBytes = ms.ToArray();
                        aesEncryptionResult.EncryptedDataBase64String = Convert.ToBase64String(aesEncryptionResult.EncryptedDataBytes);
                        aesEncryptionResult.CryptSalt = cryptSalt;
                        aesEncryptionResult.AuthSalt = authSalt;
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

            try
            {
                byte[] cryptSalt = new byte[_saltBytesLength];
                Array.Copy(encryptedStringBytes, 0, cryptSalt, 0, cryptSalt.Length);

                byte[] authSalt = new byte[_saltBytesLength];
                Array.Copy(encryptedStringBytes, cryptSalt.Length, authSalt, 0, authSalt.Length);

                // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
                byte[] cryptKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, cryptSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

                // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
                byte[] authKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, authSalt, _saltBytesLength, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

                byte[] IV = new byte[_IVBytesLength];
                Array.Copy(encryptedStringBytes, (cryptSalt.Length + authSalt.Length), IV, 0, IV.Length);

                var sentTag = new byte[_tagBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - sentTag.Length), sentTag, 0, sentTag.Length);

                var calcTag = EncryptionUtils.CalculateHMACSHA256FromDataBytes(authKey, encryptedStringBytes, 0, (encryptedStringBytes.Length - _tagBytesLength));

                if (!EncryptionUtils.TagsMatch(calcTag, sentTag))
                {
                    return new AesEncryptionResult()
                    {
                        Success = false,
                        Message = "Authentication for string decryption failed, wrong password or data tampered."
                    };
                }

                byte[] encryptedDataString = new byte[(encryptedStringBytes.Length - cryptSalt.Length - authSalt.Length - IV.Length - sentTag.Length)];
                Array.Copy(encryptedStringBytes, (cryptSalt.Length + authSalt.Length + IV.Length), encryptedDataString, 0, encryptedDataString.Length);

                var aesDecriptionResult = base.DecryptWithMemoryStream(encryptedDataString, cryptKey, IV, _cipherMode, _paddingMode);

                if (aesDecriptionResult.Success)
                {
                    aesDecriptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecriptionResult.DecryptedDataBytes);
                    aesDecriptionResult.CryptSalt = cryptSalt;
                    aesDecriptionResult.AuthSalt = authSalt;
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

        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false)
        {
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
                    #region
                    //using (FileStream fs1 = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    //{
                    //    using (FileStream fs2 = File.Open($"{encryptedFilePath}_tmp", FileMode.Create, FileAccess.Write, FileShare.None))
                    //    {
                    //        fs2.Write(cryptSalt, 0, cryptSalt.Length);
                    //        fs2.Write(authSalt, 0, authSalt.Length);
                    //        fs2.Write(aesEncryptionResult.IVOrNonce, 0, aesEncryptionResult.IVOrNonce.Length);

                    //        byte[] buffer = new byte[kBbufferSize * 1024];
                    //        int read;

                    //        while ((read = fs1.Read(buffer, 0, buffer.Length)) > 0)
                    //        {
                    //            fs2.Write(buffer, 0, read);

                    //            int percentageDone = (int)(fs1.Position * 100 / fs1.Length);
                    //            RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? $"Writing additional data ({percentageDone}%)..." : $"({percentageDone}%) written additional data."));
                    //        }
                    //    }
                    //}

                    //using (FileStream fs = File.Open(encryptedFilePath, FileMode.Append, FileAccess.Write, FileShare.None))
                    //{
                    //    fs.Write(cryptSalt, 0, cryptSalt.Length);
                    //    fs.Write(authSalt, 0, authSalt.Length);
                    //    fs.Write(aesEncryptionResult.IVOrNonce, 0, aesEncryptionResult.IVOrNonce.Length);
                    //}
                    #endregion
                    EncryptionUtils.AppendDataToFile(encryptedFilePath, aesEncryptionResult.IVOrNonce);
                    EncryptionUtils.AppendDataToFile(encryptedFilePath, authSalt);
                    EncryptionUtils.AppendDataToFile(encryptedFilePath, cryptSalt);

                    var tag = EncryptionUtils.CalculateHMACSHA256FromFile(encryptedFilePath, authKey);

                    EncryptionUtils.AppendDataToFile(encryptedFilePath, tag);

                    aesEncryptionResult.CryptSalt = cryptSalt;
                    aesEncryptionResult.AuthSalt = authSalt;
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
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Decrypted file path required."
                };
            }

            var destinationDirectory = Path.GetDirectoryName(decryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Destination directory \"{destinationDirectory}\" not found."
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
                var encryptedFileSize = new FileInfo(encryptedFilePath).Length;

                var sentTag = EncryptionUtils.GetBytesFromFile(encryptedFilePath, _tagBytesLength, (encryptedFileSize - _tagBytesLength));

                var cryptSalt = EncryptionUtils.GetBytesFromFile(encryptedFilePath, _saltBytesLength, (encryptedFileSize - _tagBytesLength - _saltBytesLength));
                var cryptKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, cryptSalt, _keyBytesLength, _iterationsForPBKDF2);

                var authSalt = EncryptionUtils.GetBytesFromFile(encryptedFilePath, _saltBytesLength, (encryptedFileSize - _tagBytesLength - (_saltBytesLength * 2)));
                var authKey = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, authSalt, _keyBytesLength, _iterationsForPBKDF2);

                var calcTag = EncryptionUtils.CalculateHMACSHA256FromFile(encryptedFilePath, authKey, 0, (encryptedFileSize - _tagBytesLength));

                var IV = EncryptionUtils.GetBytesFromFile(encryptedFilePath, _IVBytesLength, (encryptedFileSize - _tagBytesLength - (_saltBytesLength * 2) -_IVBytesLength));

                if (!EncryptionUtils.TagsMatch(calcTag, sentTag))
                {
                    return new AesEncryptionResult()
                    {
                        Success = false,
                        Message = "Authentication for file decryption failed, wrong password or data tampered."
                    };
                }

                var aesDecryptionResult = base.DecryptWithFileStream(encryptedFilePath, decryptedFilePath, cryptKey, IV, _cipherMode, _paddingMode, deleteSourceFile);

                if (aesDecryptionResult.Success)
                {
                    

                    aesDecryptionResult.CryptSalt = cryptSalt;
                    aesDecryptionResult.AuthSalt = authSalt;
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

        //public AesEncryptionResult EncryptString(string stringToEncrypt, string password)
        //{
        //    if (string.IsNullOrWhiteSpace(stringToEncrypt))
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to encrypt required."
        //        };
        //    }

        //    if (string.IsNullOrWhiteSpace(password))
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "Password required."
        //        };
        //    }

        //    try
        //    {
        //        var stringToEncryptBytes = Encoding.UTF8.GetBytes(stringToEncrypt);
        //        var passwordBytes = Encoding.UTF8.GetBytes(password);

        //        return EncryptString(stringToEncryptBytes, passwordBytes);
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

        //public AesEncryptionResult EncryptString(string stringToEncrypt, SecureString secStrPassword)
        //{
        //    if (string.IsNullOrWhiteSpace(stringToEncrypt))
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to encrypt required."
        //        };
        //    }

        //    if (secStrPassword.Length <= 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "SecureString length cannot be less or equal zero."
        //        };
        //    }

        //    byte[] passwordBytes = null;

        //    try
        //    {
        //        var stringToEncryptBytes = Encoding.UTF8.GetBytes(stringToEncrypt);

        //        //using (secStrPassword)
        //        //{
        //            passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
        //        //}

        //        return EncryptString(stringToEncryptBytes, passwordBytes);
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Error while trying to encrypt data:\n{ex.ToString()}"
        //        };
        //    }
        //    finally
        //    {
        //        if (passwordBytes != null)
        //        {
        //            Array.Clear(passwordBytes, 0, passwordBytes.Length);
        //            passwordBytes = null;
        //        }
        //    }
        //}



        //public AesEncryptionResult DecryptString(string stringToDecrypt, string password)
        //{
        //    if (string.IsNullOrWhiteSpace(stringToDecrypt))
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to decrypt required."
        //        };
        //    }

        //    if (string.IsNullOrWhiteSpace(password))
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "Password required."
        //        };
        //    }

        //    try
        //    {
        //        var stringToDecryptBytes = Convert.FromBase64String(stringToDecrypt);
        //        var passwordBytes = Encoding.UTF8.GetBytes(password);

        //        return DecryptString(stringToDecryptBytes, passwordBytes);
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
        //        };
        //    }
        //}

        //public AesEncryptionResult DecryptString(string stringToDecrypt, SecureString secStrPassword)
        //{
        //    if (string.IsNullOrWhiteSpace(stringToDecrypt))
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to decrypt required."
        //        };
        //    }

        //    if (secStrPassword.Length <= 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "SecureString length cannot be less or equal zero."
        //        };
        //    }

        //    byte[] passwordBytes = null;

        //    try
        //    {
        //        var stringToDecryptBytes = Convert.FromBase64String(stringToDecrypt);

        //        //using (secStrPassword)
        //        //{
        //            passwordBytes = EncryptionUtils.ConvertSecureStringToByteArray(secStrPassword);
        //        //}

        //        return DecryptString(stringToDecryptBytes, passwordBytes);
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
        //        };
        //    }
        //    finally
        //    {
        //        if (passwordBytes != null)
        //        {
        //            Array.Clear(passwordBytes, 0, passwordBytes.Length);
        //            passwordBytes = null;
        //        }
        //    }
        //}

        #endregion public methods
    }
}
