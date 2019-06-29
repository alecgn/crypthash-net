using CryptHash.Net.Encryption.AES.EncryptionResults;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.AES.Base
{
    public class AesBase
    {
        private int _keyBitSize;
        private byte[] _key;
        private int _blockBitSize;
        private byte[] _IV;
        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;
        private int _feedbackBitSize;
        private static readonly int[] _allowedKeyBitSizes = new int[] { 128, 192, 256 };
        private static readonly int _allowedBlockBitSize = 128;

        public AesBase() { }

        public AesBase(int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize)
        {
            _keyBitSize = keyBitSize;
            _key = key;
            _blockBitSize = blockBitSize;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _feedbackBitSize = feedbackBitSize;
        }

        public AesEncryptionResult EncryptWithMemoryStream(byte[] sourceData, int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize)
        {
            if (sourceData == null || sourceData.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Source data cannot be null or 0 bytes.",
                    EncryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            if (!_allowedKeyBitSizes.Contains(keyBitSize))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Key bit size ({keyBitSize}) invalid. Must be one of the follwing: ({string.Join(",", _allowedKeyBitSizes)}).",
                    EncryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            if (blockBitSize != _allowedBlockBitSize)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Block bit size ({blockBitSize} invalid. Must be: ({_allowedBlockBitSize}).)",
                    EncryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            if (cipherMode.Equals(CipherMode.CFB) && blockBitSize == _allowedBlockBitSize && feedbackBitSize != _allowedBlockBitSize)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Feedback bit size ({feedbackBitSize} invalid when using CFB mode and block bit size ({_allowedBlockBitSize}). Must be: ({_allowedBlockBitSize}).)",
                    EncryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            _keyBitSize = keyBitSize;
            _key = key;
            _blockBitSize = blockBitSize;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _feedbackBitSize = feedbackBitSize;

            byte[] encryptedData = null;

            try
            {
                using (AesManaged aesManaged = new AesManaged())
                {
                    aesManaged.KeySize = _keyBitSize;

                    if (_key == null || _key.Length == 0)
                    {
                        aesManaged.GenerateKey();
                        _key = aesManaged.Key;
                    }
                    else
                        aesManaged.Key = _key;

                    aesManaged.BlockSize = _blockBitSize;

                    if (_IV == null || _IV.Length == 0)
                    {
                        aesManaged.GenerateIV();
                        _IV = aesManaged.IV;
                    }
                    else
                        aesManaged.IV = _IV;

                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;
                    aesManaged.FeedbackSize = _feedbackBitSize;

                    using (var encryptor = aesManaged.CreateEncryptor(_key, _IV))
                    {
                        using (var ms = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                using (var bw = new BinaryWriter(cs))
                                {
                                    bw.Write(sourceData);
                                }
                            }

                            encryptedData = ms.ToArray();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to encrypt data:\n{ex.ToString()}",
                    EncryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            return new AesEncryptionResult()
            {
                Success = true,
                Message = "Data succesfully encrypted.",
                EncryptedDataBytes = encryptedData,
                Key = _key,
                IVOrNonce = _IV
            };
        }

        public AesEncryptionResult DecryptWithMemoryStream(byte[] encryptedData, int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Encrypted data cannot be null or 0 bytes.",
                    DecryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            if (!_allowedKeyBitSizes.Contains(keyBitSize))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Key bit size ({keyBitSize} invalid. Must be one of the follwing: ({string.Join(",", _allowedKeyBitSizes)}).)",
                    DecryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            if (blockBitSize != _allowedBlockBitSize)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Block bit size ({blockBitSize} invalid. Must be: ({_allowedBlockBitSize}).)",
                    DecryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            if (cipherMode.Equals(CipherMode.CFB) && blockBitSize == _allowedBlockBitSize && feedbackBitSize != _allowedBlockBitSize)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Feedback bit size ({feedbackBitSize} invalid when using CFB mode and block bit size ({_allowedBlockBitSize}). Must be: ({_allowedBlockBitSize}).)",
                    DecryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            _keyBitSize = keyBitSize;
            _key = key;
            _blockBitSize = blockBitSize;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _feedbackBitSize = feedbackBitSize;

            byte[] decryptedData = null;

            try
            {
                using (AesManaged aesManaged = new AesManaged())
                {
                    aesManaged.KeySize = _keyBitSize;
                    aesManaged.Key = _key;
                    aesManaged.BlockSize = _blockBitSize;
                    aesManaged.IV = _IV;
                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;
                    aesManaged.FeedbackSize = _feedbackBitSize;

                    using (var decryptor = aesManaged.CreateDecryptor(_key, _IV))
                    {
                        using (var ms = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                            {
                                using (var bw = new BinaryWriter(cs))
                                {
                                    bw.Write(encryptedData);
                                }
                            }

                            decryptedData = ms.ToArray();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to decrypt data:\n{ex.ToString()}",
                    DecryptedDataBytes = null,
                    Key = null,
                    IVOrNonce = null
                };
            }

            return new AesEncryptionResult()
            {
                Success = true,
                Message = "Data succesfully decrypted.",
                DecryptedDataBytes = decryptedData,
                Key = _key,
                IVOrNonce = _IV
            };
        }

        public AesEncryptionResult EncryptWithFileStream()
        {
            throw new NotImplementedException();
        }

        public AesEncryptionResult DecryptWithFileStream()
        {
            throw new NotImplementedException();
        }
    }
}
