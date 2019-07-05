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
    // not using "abstract" keyword to allow direct use/instantiation of this base class, case desired...
    public class AesBase
    {
        #region events

        public event OnEncryptionMessageHandler OnEncryptionMessage;

        public event OnEncryptionProgressHandler OnEncryptionProgress;

        #endregion events


        #region fields

        private int _keyBitSize;
        private byte[] _key;
        private int _blockBitSize;
        private byte[] _IV;
        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;
        private int _feedbackBitSize;
        private static readonly int[] _allowedKeyBitSizes = new int[] { 128, 192, 256 };
        private static readonly int _allowedBlockBitSize = 128;
        private static readonly int _allowedIVBitSize = 128;

        #endregion fields


        #region constructors

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

        #endregion constructors


        #region public methods

        public AesEncryptionResult EncryptWithMemoryStream(byte[] sourceData, byte[] key = null, byte[] IV = null, CipherMode cipherMode = CipherMode.CBC, 
            PaddingMode paddingMode = PaddingMode.PKCS7, int keyBitSize = 256, int blockBitSize = 128, int feedbackBitSize = 128)
        {
            if (sourceData == null || sourceData.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Source data cannot be null or 0 bytes."
                };
            }

            if (key != null)
            {
                if (!_allowedKeyBitSizes.Contains((key.Length * 8)))
                {
                    return new AesEncryptionResult()
                    {
                        Success = false,
                        Message = $"Key bit size ({(key.Length * 8)}) invalid. Must be one of the following: ({string.Join(",", _allowedKeyBitSizes)})."
                    };
                }
            }

            if (IV != null)
            {
                if ((IV.Length * 8) != _allowedIVBitSize)
                {
                    return new AesEncryptionResult()
                    {
                        Success = false,
                        Message = $"IV bit size ({(IV.Length * 8)}) invalid. Must be: ({_allowedIVBitSize})."
                    };
                }
            }

            if (!_allowedKeyBitSizes.Contains(keyBitSize))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Key bit size ({keyBitSize}) invalid. Must be one of the following: ({string.Join(",", _allowedKeyBitSizes)})."
                };
            }

            if (blockBitSize != _allowedBlockBitSize)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Block bit size ({blockBitSize} invalid. Must be: ({_allowedBlockBitSize})."
                };
            }

            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _keyBitSize = keyBitSize;
            _blockBitSize = blockBitSize;
            _feedbackBitSize = feedbackBitSize;

            byte[] encryptedData = null;

            try
            {
                using (AesManaged aesManaged = new AesManaged())
                {
                    if (_key == null)
                    {
                        aesManaged.GenerateKey();
                        _key = aesManaged.Key;
                    }
                    else
                        aesManaged.Key = _key;

                    if (_IV == null)
                    {
                        aesManaged.GenerateIV();
                        _IV = aesManaged.IV;
                    }
                    else
                        aesManaged.IV = _IV;

                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;
                    aesManaged.KeySize = _keyBitSize;
                    aesManaged.BlockSize = _blockBitSize;
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
                    Message = $"Error while trying to encrypt data:\n{ex.ToString()}"
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

        public AesEncryptionResult DecryptWithMemoryStream(byte[] encryptedData, byte[] key, byte[] IV, CipherMode cipherMode = CipherMode.CBC, 
            PaddingMode paddingMode = PaddingMode.PKCS7, int keyBitSize = 256, int blockBitSize = 128, int feedbackBitSize = 128)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Encrypted data cannot be null or 0 bytes."
                };
            }

            if (key == null || key.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Key cannot be null or 0 bytes."
                };
            }

            if (IV == null || IV.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "IV cannot be null or 0 bytes."
                };
            }

            //if (!_allowedKeyBitSizes.Contains(keyBitSize))
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Key bit size ({keyBitSize} invalid. Must be one of the following: ({string.Join(",", _allowedKeyBitSizes)}).)"
            //    };
            //}

            //if (blockBitSize != _allowedBlockBitSize)
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Block bit size ({blockBitSize} invalid. Must be: ({_allowedBlockBitSize}).)"
            //    };
            //}

            //if (cipherMode.Equals(CipherMode.CFB) && blockBitSize == _allowedBlockBitSize && feedbackBitSize != _allowedBlockBitSize)
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Feedback bit size ({feedbackBitSize} invalid when using CFB mode and block bit size ({_allowedBlockBitSize}). Must be: ({_allowedBlockBitSize}).)"
            //    };
            //}

            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _keyBitSize = keyBitSize;
            _blockBitSize = blockBitSize;
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
                    Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
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
        
        public AesEncryptionResult EncryptWithFileStream(string sourceFilePath, string encryptedFilePath, int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize, bool deleteSourceFile = false, int kBbufferSize = 4)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Source file \"{sourceFilePath}\" not found."
                };
            }

            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Encrypted file path required."
                };
            }

            var destinationDirectory = Path.GetDirectoryName(encryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Destination directory \"{destinationDirectory}\" not found."
                };
            }

            //if (!_allowedKeyBitSizes.Contains(keyBitSize))
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Key bit size ({keyBitSize}) invalid. Must be one of the following: ({string.Join(",", _allowedKeyBitSizes)})."
            //    };
            //}

            //if (blockBitSize != _allowedBlockBitSize)
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Block bit size ({blockBitSize} invalid. Must be: ({_allowedBlockBitSize}).)"
            //    };
            //}

            //if (cipherMode.Equals(CipherMode.CFB) && blockBitSize == _allowedBlockBitSize && feedbackBitSize != _allowedBlockBitSize)
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Feedback bit size ({feedbackBitSize} invalid when using CFB mode and block bit size ({_allowedBlockBitSize}). Must be: ({_allowedBlockBitSize}).)"
            //    };
            //}

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
                                        RaiseOnEncryptionProgress(percentageDone, $"{percentageDone}% encrypted{(percentageDone != 100 ? "..." : ".")}");
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(sourceFilePath);
                    File.Move(encryptedFilePath + "_tmp", encryptedFilePath);
                }

                if (deleteSourceFile && !pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(sourceFilePath);
                }

                var message = $"File \"{sourceFilePath}\" successfully encrypted to \"{encryptedFilePath}\".";
                message += (deleteSourceFile && !pathsEqual ? $"\nFile \"{sourceFilePath}\" deleted." : "");

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = message,
                    Key = _key,
                    IVOrNonce = _IV
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to encrypt data:\n{ex.ToString()}"
                };
            }
        }

        public AesEncryptionResult DecryptWithFileStream(string encryptedFilePath, string decryptedFilePath, int keyBitSize, byte[] key, int blockBitSize, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode, int feedbackBitSize, bool deleteEncryptedFile = false, int kBbufferSize = 4)
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

            //if (!_allowedKeyBitSizes.Contains(keyBitSize))
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Key bit size ({keyBitSize}) invalid. Must be one of the following: ({string.Join(",", _allowedKeyBitSizes)})."
            //    };
            //}

            //if (blockBitSize != _allowedBlockBitSize)
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Block bit size ({blockBitSize} invalid. Must be: ({_allowedBlockBitSize}).)"
            //    };
            //}

            //if (cipherMode.Equals(CipherMode.CFB) && blockBitSize == _allowedBlockBitSize && feedbackBitSize != _allowedBlockBitSize)
            //{
            //    return new AesEncryptionResult()
            //    {
            //        Success = false,
            //        Message = $"Feedback bit size ({feedbackBitSize} invalid when using CFB mode and block bit size ({_allowedBlockBitSize}). Must be: ({_allowedBlockBitSize}).)"
            //    };
            //}

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
                                        RaiseOnEncryptionProgress(percentageDone, $"{percentageDone}% decrypted{(percentageDone != 100 ? "..." : ".")}");
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(encryptedFilePath);
                    File.Move(decryptedFilePath + "_tmp", decryptedFilePath);
                }

                if (deleteEncryptedFile && !pathsEqual)
                {
                    Utils.EncryptionUtils.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(encryptedFilePath);
                }

                var message = $"File \"{encryptedFilePath}\" successfully decrypted to \"{decryptedFilePath}\".";
                message += (deleteEncryptedFile && !pathsEqual ? $"\nFile \"{encryptedFilePath}\" deleted." : "");

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = message,
                    Key = _key,
                    IVOrNonce = _IV
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"Error while trying to decrypt data:\n{ex.ToString()}"
                };
            }
        }

        #endregion public methods


        #region private methods

        private void RaiseOnEncryptionMessage(string message)
        {
            OnEncryptionMessage?.Invoke(message);
        }

        private void RaiseOnEncryptionProgress(int percentageDone, string message)
        {
            OnEncryptionProgress?.Invoke(percentageDone, message);
        }

        #endregion private methods
    }
}
