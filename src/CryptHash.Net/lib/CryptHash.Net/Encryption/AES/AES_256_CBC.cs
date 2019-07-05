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

        //public AesEncryptionResult EncryptString(byte[] stringToEncryptBytes, byte[] passwordBytes, byte[] salt = null, byte[] IV = null)
        //{
        //    if (stringToEncryptBytes == null || stringToEncryptBytes.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to encrypt required."
        //        };
        //    }

        //    if (passwordBytes == null || passwordBytes.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "Password required."
        //        };
        //    }

        //    try
        //    {
        //        if (salt == null || salt.Length == 0)
        //        {
        //            salt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);
        //        }

        //        // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
        //        byte[] key = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, _keyBytesLength, salt, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

        //        var aesEncryptionResult = base.EncryptWithMemoryStream(stringToEncryptBytes, _keyBitSize, key, _blockBitSize, null, _cipherMode, _paddingMode, _feedbackSize);

        //        if (aesEncryptionResult.Success)
        //        {
        //            //using (var ms = new MemoryStream())
        //            //{
        //                //using (var bw = new BinaryWriter(ms))
        //                //{
        //                    //bw.Write(salt);
        //                    //bw.Write(aesEncryptionResult.IVOrNonce);
        //                    //bw.Write(aesEncryptionResult.EncryptedDataBytes);
        //                //}

        //                //aesEncryptionResult.EncryptedDataBytes = ms.ToArray();
        //                aesEncryptionResult.EncryptedDataBase64String = Convert.ToBase64String(aesEncryptionResult.EncryptedDataBytes);
        //                aesEncryptionResult.Salt = salt;
        //            //}
        //        }

        //        return aesEncryptionResult;
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

        //public AesEncryptionResult DecryptString(byte[] stringToDecryptBytes, byte[] passwordBytes, byte[] IV, byte[] salt)
        //{
        //    if (stringToDecryptBytes == null || stringToDecryptBytes.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "String to decrypt required."
        //        };
        //    }

        //    if (passwordBytes == null || passwordBytes.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "Password required."
        //        };
        //    }

        //    if (IV == null || IV.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "IV required."
        //        };
        //    }

        //    if (salt == null || salt.Length == 0)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = "Salt required."
        //        };
        //    }

        //    try
        //    {
        //        //byte[] salt = new byte[_saltBytesLength];
        //        //Array.Copy(stringToDecryptBytes, 0, salt, 0, salt.Length);

        //        // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
        //        byte[] key = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, _keyBytesLength, salt, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

        //        byte[] IV = new byte[_IVBytesLength];
        //        Array.Copy(stringToDecryptBytes, salt.Length, IV, 0, IV.Length);

        //        byte[] encryptedStringData = new byte[(stringToDecryptBytes.Length - salt.Length - IV.Length)];
        //        Array.Copy(stringToDecryptBytes, (salt.Length + IV.Length), encryptedStringData, 0, encryptedStringData.Length);

        //        var aesDecriptionResult = base.DecryptWithMemoryStream(encryptedStringData, _keyBitSize, key, _blockBitSize, IV, _cipherMode, _paddingMode, _feedbackSize);

        //        if (aesDecriptionResult.Success)
        //            aesDecriptionResult.DecryptedDataString = Encoding.UTF8.GetString(aesDecriptionResult.DecryptedDataBytes);

        //        return aesDecriptionResult;
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AesEncryptionResult()
        //        {
        //            Success = false,
        //            Message = ex.ToString(),
        //            DecryptedDataBytes = null,
        //            DecryptedDataString = null
        //        };
        //    }
        //}

        //public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, string password, bool deleteSourceFile = false)
        //{

        //    byte[] salt = EncryptionUtils.GenerateRandomBytes(_saltBytesLength);

        //    // EncryptionUtils.GetBytesFromPBKDF2(...) relies on Rfc2898DeriveBytes, still waiting for full .net standard 2.1 implementation of Rfc2898DeriveBytes that accepts HashAlgorithmName as parameter, current version 2.0 does not support it yet.
        //    byte[] key = EncryptionUtils.GetBytesFromPBKDF2(passwordBytes, _keyBytesLength, salt, _iterationsForPBKDF2/*, HashAlgorithmName.SHA256*/);

        //    return base.EncryptWithFileStream(sourceFilePath, encryptedFilePath, _keyBitSize, key, _blockBitSize);
        //}

        //public AesEncryptionResult DecryptFile()
        //{
        //    return base.DecryptWithFileStream();
        //}


    }
}
