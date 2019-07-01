/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.Utils.EventHandlers;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.AES.Base
{
    // not using "abstract" keyword to allow direct use/instantiation of this class, case desired...
    public class AesBase
    {
        #region Fields

        private int _keyBitSize;
        private byte[] _key;
        private int _blockBitSize;
        private byte[] _IV;
        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;
        private int _feedbackBitSize;
        private static readonly int[] _allowedKeyBitSizes = new int[] { 128, 192, 256 };
        private static readonly int _allowedBlockBitSize = 128;

        #endregion Fields


        #region Events

        public event OnEncryptionMessageHandler OnEncryptionMessage;

        public event OnEncryptionProgressHandler OnEncryptionProgress;

        #endregion Events

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

        private AesEncryptionResult EncryptWithFileStream(string sourceFilePath, string encryptedFilePath, int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize, bool deleteSourceFile = false, int kBbufferSize = 4)
        {
            if (!File.Exists(sourceFilePath))
            {
                throw new FileNotFoundException($"File \"{sourceFilePath}\" not found.", sourceFilePath);
            }

            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                throw new ArgumentException("Encrypted file path required.", nameof(encryptedFilePath));
            }

            var destinationDirectory = Path.GetDirectoryName(encryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                throw new DirectoryNotFoundException($"Directory \"{destinationDirectory}\" not found.");
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

            bool pathsEqual = encryptedFilePath.Equals(sourceFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
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
                        using (FileStream sourceFs = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            using (FileStream encryptedFs = File.Open((pathsEqual ? encryptedFilePath + "_tmp" : encryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                using (CryptoStream cs = new CryptoStream(encryptedFs, encryptor, CryptoStreamMode.Write))
                                {
                                    //plain.CopyTo(cs);

                                    byte[] buffer = new byte[kBbufferSize * 1024];
                                    int read;

                                    while ((read = sourceFs.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        cs.Write(buffer, 0, read);

                                        int percentageDone = (int)(sourceFs.Position * 100 / sourceFs.Length);
                                        RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? "Encrypting..." : "Encrypted. Wait for authentication tag calculation..."));
                                    }

                                    cs.Close();
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(sourceFilePath);
                    File.Delete(sourceFilePath);
                    File.Move(encryptedFilePath + "_tmp", encryptedFilePath);
                }

                if (deleteSourceFile && !pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(sourceFilePath);
                    File.Delete(sourceFilePath);
                }

                var message = $"File \"{sourceFilePath}\" successfully encrypted to \"{encryptedFilePath}\".";
                message += (deleteSourceFile && !pathsEqual ? $"\nFile \"{sourceFilePath}\" deleted." : "");

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = message,
                    EncryptedDataBytes = null,
                    EncryptedDataString = null,
                    Key = _key,
                    IVOrNonce = _IV
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    EncryptedDataBytes = null,
                    EncryptedDataString = null,
                    Key = null,
                    IVOrNonce = null
                };
            }
        }

        private AesEncryptionResult DecryptWithFileStream(string encryptedFilePath, string decryptedFilePath, int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize, bool deleteEncryptedFile = false, int kBbufferSize = 4)
        {
            if (!File.Exists(encryptedFilePath))
            {
                throw new FileNotFoundException($"File \"{encryptedFilePath}\" not found.", encryptedFilePath);
            }

            if (string.IsNullOrWhiteSpace(decryptedFilePath))
            {
                throw new ArgumentException("Decrypted file path required.", nameof(decryptedFilePath));
            }

            var destinationDirectory = Path.GetDirectoryName(decryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                throw new DirectoryNotFoundException($"Directory \"{destinationDirectory}\" not found.");
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

            bool pathsEqual = decryptedFilePath.Equals(encryptedFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    aesManaged.KeySize = _keyBitSize;
                    aesManaged.Key = _key;
                    aesManaged.BlockSize = _blockBitSize;
                    aesManaged.IV = _IV;
                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;
                    aesManaged.FeedbackSize = _feedbackBitSize;

                    using (FileStream decryptedFs = File.Open((pathsEqual ? decryptedFilePath + "_tmp" : decryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        using (FileStream encryptedFs = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            using (var decryptor = aesManaged.CreateDecryptor(_key, _IV))
                            {
                                using (CryptoStream cs = new CryptoStream(decryptedFs, decryptor, CryptoStreamMode.Write))
                                {
                                    //encrypted.CopyTo(cs);

                                    byte[] buffer = new byte[kBbufferSize * 1024];
                                    int read;

                                    while ((read = encryptedFs.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        cs.Write(buffer, 0, read);

                                        int percentageDone = (int)(encryptedFs.Position * 100 / encryptedFs.Length);
                                        RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? "Decrypting..." : "Decrypted."));
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(encryptedFilePath);
                    File.Delete(encryptedFilePath);
                    File.Move(decryptedFilePath + "_tmp", decryptedFilePath);
                }

                if (deleteEncryptedFile && !pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(encryptedFilePath);
                    File.Delete(encryptedFilePath);
                }

                var message = $"File \"{encryptedFilePath}\" successfully decrypted to \"{decryptedFilePath}\".";
                message += (deleteEncryptedFile && !pathsEqual ? $"\nFile \"{encryptedFilePath}\" deleted." : "");

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = message,
                    DecryptedDataBytes = null,
                    DecryptedDataString = null,
                    Key = _key,
                    IVOrNonce = _IV
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                    DecryptedDataBytes = null,
                    DecryptedDataString = null,
                    Key = null,
                    IVOrNonce = null
                };
            }
        }


        private void RaiseOnEncryptionMessage(string message)
        {
            OnEncryptionMessage?.Invoke(message);
        }

        private void RaiseOnEncryptionProgress(int percentageDone, string message)
        {
            OnEncryptionProgress?.Invoke(percentageDone, message);
        }
    }
}
