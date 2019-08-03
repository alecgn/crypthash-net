///*
// *      Alessandro Cagliostro, 2019
// *      
// *      https://github.com/alecgn
// */

//using System;
//using System.Linq;
//using System.Security.Cryptography;
//using CryptHash.Net.Encryption.AES.EncryptionResults;
//using CryptHash.Net.Encryption.Utils;

////#if (NETCOREAPP3_0 || NETSTANDARD2_1)
//namespace CryptHash.Net.Encryption.AES.AEAD.Base
//{
//    public abstract class AesGcmBase
//    {
//#region fields

//        private byte[] _key;
//        private byte[] _nonce;

//        // Maximum input size -> 2^39 - 256 bits
//        // (long)((Math.Pow(2, 39) - 256) / 8) -> 68,719,476,704 bytes or ≅ 63.9 gigaBytes...
//        private const long _maxInputDataSizeBytes = 68719476704;

//        // Maximum input authenticated data size -> 2^64 - 1 bit
//        // (long)((BigInteger.Pow(2, 64) - 1) / 8) -> 2,305,843,009,213,693,951 bytes or ≅ 2,147,483,647 gigaBytes or 2,097,151 teraBytes...
//        private const long _maxInputAuthDataSizeBytes = 2305843009213693951;

//        private static readonly int[] _allowedKeyBitSizes = new int[] { 128, 192, 256 };
//        private const int _allowedNonceBitSize = 96;
//        private const int _allowedTagBitSize = 128;


//#endregion private fields


//#region constructors

//        internal AesGcmBase() { }

//        internal AesGcmBase(byte[] key, byte[] nonce)
//        {
//            _key = key;
//            _nonce = nonce;
//        }

//#endregion constructors


//#region internal methods

//        internal AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] key, byte[] nonce, byte[] associatedData = null)
//        {
//            if (plainStringBytes == null || plainStringBytes.Length == 0)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = "String to encrypt required."
//                };
//            }

//            if (plainStringBytes.LongLength > _maxInputDataSizeBytes)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Max. string length cannot be greater than {_maxInputDataSizeBytes} bytes."
//                };
//            }

//            if (key == null)
//            {
//                //key = new byte[32];
//                //RandomNumberGenerator.Fill(key);
//                key = EncryptionUtils.GenerateRandomBytes((_allowedKeyBitSizes.Max() / 8));
//            }

//            if (!_allowedKeyBitSizes.Contains((key.Length * 8)))
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Invalid key bit size: ({(key.Length * 8)}). Must be one of the following sizes: ({string.Join(", ", _allowedKeyBitSizes)})."
//                };
//            }

//            if (nonce == null)
//            {
//                //nonce = new byte[12];
//                //RandomNumberGenerator.Fill(nonce);
//                nonce = EncryptionUtils.GenerateRandomBytes((_allowedNonceBitSize / 8));
//            }

//            if ((nonce.Length * 8) != _allowedNonceBitSize)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Invalid nonce bit size: ({(nonce.Length * 8)}). Must be: ({_allowedNonceBitSize})."
//                };
//            }

//            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
//                };
//            }

//            _key = key;
//            _nonce = nonce;

//            byte[] tag = new byte[(_allowedTagBitSize / 8)];
//            byte[] encryptedData = new byte[plainStringBytes.Length];

//            try
//            {
//                using (var aesGcm = new AesGcm(_key))
//                {
//                    aesGcm.Encrypt(_nonce, plainStringBytes, encryptedData, tag, associatedData);
//                }

//                return new AesEncryptionResult()
//                {
//                    Success = true,
//                    Message = "Data succesfully encrypted.",
//                    EncryptedDataBytes = encryptedData,
//                    DecryptedDataBytes = null,
//                    Tag = tag,
//                    Key = _key,
//                    Nonce = _nonce
//                };
//            }
//            catch (Exception ex)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Error while trying to encrypt data:\n{ex.ToString()}"
//                };
//            }
//        }

//        public AesEncryptionResult Decrypt(byte[] encryptedData, byte[] key, byte[] tag, byte[] nonce, byte[] associatedData = null)
//        {
//            if (encryptedData == null || encryptedData.Length == 0)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = "Encrypted data cannot be null or 0 length."
//                };
//            }

//            if (encryptedData.LongLength > _maxInputDataSizeBytes)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Max. encrypted data length cannot be greater than {_maxInputDataSizeBytes} bytes."
//                };
//            }

//            if (key == null)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Key cannot be null."
//                };
//            }

//            if (!_allowedKeyBitSizes.Contains((key.Length * 8)))
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Invalid key bit size: ({(key.Length * 8)}). Must be one of the following sizes: ({string.Join(", ", _allowedKeyBitSizes)})."
//                };
//            }

//            if (tag == null)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Tag cannot be null."
//                };
//            }

//            if ((tag.Length * 8) != _allowedTagBitSize)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Invalid tag bit size: ({(tag.Length * 8)}). Must be: ({_allowedTagBitSize})."
//                };
//            }

//            if (nonce == null)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Nonce cannot be null."
//                };
//            }

//            if ((nonce.Length * 8) != _allowedNonceBitSize)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Invalid nonce bit size: ({(nonce.Length * 8)}). Must be: ({_allowedNonceBitSize})."
//                };
//            }

//            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Max. associated data length cannot be greater than {_maxInputAuthDataSizeBytes} bytes."
//                };
//            }

//            _key = key;
//            _nonce = nonce;

//            byte[] decryptedData = new byte[encryptedData.Length];

//            try
//            {
//                using (var aesGcm = new AesGcm(_key))
//                {
//                    aesGcm.Decrypt(_nonce, encryptedData, tag, decryptedData, associatedData);
//                }

//                return new AesEncryptionResult()
//                {
//                    Success = true,
//                    Message = "Data succesfully decrypted.",
//                    EncryptedDataBytes = null,
//                    DecryptedDataBytes = decryptedData,
//                    Tag = tag,
//                    Key = _key,
//                    Nonce = _nonce
//                };
//            }
//            catch (Exception ex)
//            {
//                return new AesEncryptionResult()
//                {
//                    Success = false,
//                    Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
//                };
//            }
//        }

//#endregion public methods
//    }
//}
////#endif