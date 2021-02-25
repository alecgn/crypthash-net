/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.RSA.EncryptionResults;
using CryptHash.Net.Util;
using System;
using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.RSA.Base
{
    /*internal abstract*/
    public class RSABase
    {
        public static KeySizes KeySizes = new KeySizes(384, 16384, 8);

        public static bool IsValidKeySize(int keySize)
        {
            return (keySize >= KeySizes.MinSize && keySize <= KeySizes.MaxSize && keySize % KeySizes.SkipSize == 0);
        }

        public RSAEncryptionResult Encrypt(byte[] sourceData, int keySize, RSAParameters rsaParameters, bool doOAEPPadding = false)
        {
            if (!IsValidKeySize(keySize))
            {
                return new RSAEncryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.InvalidKeySizeError"]} ({keySize})."
                };
            }

            byte[] encryptedData = null;

            try
            {
                using (var rsaCsp = new RSACryptoServiceProvider(keySize))
                {
                    rsaCsp.ImportParameters(rsaParameters);
                    encryptedData = rsaCsp.Encrypt(sourceData, doOAEPPadding);
                }
            }
            catch (Exception ex)
            {
                return new RSAEncryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Encryption.ExceptionError"]}\n{ex.ToString()}"
                };
            }

            return new RSAEncryptionResult()
            {
                Success = true,
                Message = MessageDictionary.Instance["Encryption.EncryptSuccess"],
                RSAParameters = rsaParameters,
                EncryptedDataBytes = encryptedData
            };
        }

        public RSADecryptionResult Decrypt(byte[] encryptedData, int keySize, RSAParameters rsaParameters, bool doOAEPPadding)
        {
            if (!IsValidKeySize(keySize))
            {
                return new RSADecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.InvalidKeySizeError"]} ({keySize})."
                };
            }

            byte[] decryptedData = null;

            try
            {
                using (var rsaCsp = new RSACryptoServiceProvider(keySize))
                {
                    rsaCsp.ImportParameters(rsaParameters);
                    decryptedData = rsaCsp.Decrypt(encryptedData, doOAEPPadding);
                }
            }
            catch (Exception ex)
            {
                return new RSADecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Encryption.ExceptionError"]}\n{ex.ToString()}"
                };
            }

            return new RSADecryptionResult()
            {
                Success = true,
                Message = MessageDictionary.Instance["Encryption.EncryptSuccess"],
                RSAParameters = rsaParameters,
                DecryptedDataBytes = decryptedData
            };
        }
    }
}
