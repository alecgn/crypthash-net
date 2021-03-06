﻿/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.AES.Enums;
using CryptHash.Net.Resources;
using CryptHash.Net.Util;
using CryptHash.Net.Util.EventHandlers;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.AES.Base
{
    public abstract class AesBase
    {
        #region events

        public event OnEncryptionMessageHandler OnEncryptionMessage;
        public event OnDecryptionMessageHandler OnDecryptionMessage;
        public event OnEncryptionProgressHandler OnEncryptionProgress;
        public event OnDecryptionProgressHandler OnDecryptionProgress;

        #endregion events


        #region fields

        private byte[] _key = null;
        private byte[] _IV = null;

        #endregion fields


        #region constructors

        internal AesBase() { }

        internal AesBase(byte[] key, byte[] IV)
        {
            _key = key;
            _IV = IV;
        }

        #endregion constructors


        #region internal methods

        internal AesEncryptionResult EncryptWithMemoryStream(byte[] sourceData, byte[] key = null, byte[] IV = null, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (sourceData == null || sourceData.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputRequired
                };
            }

            _key = key ?? _key;
            _IV = IV ?? _IV;

            byte[] encryptedData = null;

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    if (_key == null)
                    {
                        aesManaged.GenerateKey();
                        _key = aesManaged.Key;
                    }
                    else
                    {
                        if (aesManaged.ValidKeySize((_key.Length * 8)))
                        {
                            aesManaged.Key = _key;
                        }
                        else
                        {
                            return new AesEncryptionResult()
                            {
                                Success = false,
                                Message = $"{MessageStrings.Common_InvalidKeySizeError} ({(_key.Length * 8)})."
                            };
                        }
                    }

                    if (_IV == null)
                    {
                        aesManaged.GenerateIV();
                        _IV = aesManaged.IV;
                    }
                    else
                    {
                        aesManaged.IV = _IV;
                    }

                    aesManaged.Mode = cipherMode;
                    aesManaged.Padding = paddingMode;

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
                    Message = $"{MessageStrings.Encryption_ExceptionError}\n{ex.ToString()}"
                };
            }

            return new AesEncryptionResult()
            {
                Success = true,
                Message = MessageStrings.Encryption_EncryptSuccess,
                EncryptedDataBytes = encryptedData,
                EncryptedDataBase64String = Convert.ToBase64String(encryptedData),
                Key = _key,
                IV = _IV,
                AesCipherMode = (AesCipherMode)cipherMode,
                PaddingMode = paddingMode
            };
        }

        internal AesDecryptionResult DecryptWithMemoryStream(byte[] encryptedData, byte[] key = null, byte[] IV = null, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputRequired
                };
            }

            _key = key ?? _key;
            _IV = IV ?? _IV;

            if (_key == null)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_NullKeyError
                };
            }

            if (_IV == null)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_NullIVError
                };
            }

            byte[] decryptedData = null;

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    if (aesManaged.ValidKeySize((_key.Length * 8)))
                    {
                        aesManaged.Key = _key;
                    }
                    else
                    {
                        return new AesDecryptionResult()
                        {
                            Success = false,
                            Message = $"{MessageStrings.Common_InvalidKeySizeError} ({(_key.Length * 8)})."
                        };
                    }

                    aesManaged.IV = _IV;
                    aesManaged.Mode = cipherMode;
                    aesManaged.Padding = paddingMode;

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
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Decryption_ExceptionError}\n{ex.ToString()}"
                };
            }

            return new AesDecryptionResult()
            {
                Success = true,
                Message = MessageStrings.Decryption_DecryptSuccess,
                DecryptedDataBytes = decryptedData,
                DecryptedDataString = System.Text.Encoding.UTF8.GetString(decryptedData),
                Key = _key,
                IV = _IV,
                AesCipherMode = (AesCipherMode)cipherMode,
                PaddingMode = paddingMode
            };
        }

        internal AesEncryptionResult EncryptWithFileStream(string sourceFilePath, string encryptedFilePath, byte[] key = null, byte[] IV = null, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7, bool deleteSourceFile = false, int kBbufferSize = 4)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    //Message = $"{MessageStrings.Common_FileNotFound} \"{sourceFilePath}\"."
                    Message = $"{MessageStrings.Common_FileNotFound} \"{sourceFilePath}\"."
                };
            }

            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_EncryptedFilePathError
                };
            }

            var destinationDirectory = Path.GetDirectoryName(encryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Encryption_DestinationDirectoryNotFound} \"{destinationDirectory}\"."
                };
            }

            _key = key ?? _key;
            _IV = IV ?? _IV;

            var pathsEqual = encryptedFilePath.Equals(sourceFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    if (_key == null)
                    {
                        aesManaged.GenerateKey();
                        _key = aesManaged.Key;
                    }
                    else
                    {
                        if (aesManaged.ValidKeySize((_key.Length * 8)))
                        {
                            aesManaged.Key = _key;
                        }
                        else
                        {
                            return new AesEncryptionResult()
                            {
                                Success = false,
                                Message = $"{MessageStrings.Common_InvalidKeySizeError} ({(_key.Length * 8)})."
                            };
                        }
                    }

                    if (_IV == null || _IV.Length == 0)
                    {
                        aesManaged.GenerateIV();
                        _IV = aesManaged.IV;
                    }
                    else
                    {
                        aesManaged.IV = _IV;
                    }

                    aesManaged.Mode = cipherMode;
                    aesManaged.Padding = paddingMode;

                    using (var encryptor = aesManaged.CreateEncryptor(_key, _IV))
                    {
                        using (var sourceFs = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            using (var encryptedFs = File.Open((pathsEqual ? encryptedFilePath + "_tmpcrypt" : encryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                using (var cs = new CryptoStream(encryptedFs, encryptor, CryptoStreamMode.Write))
                                {
                                    //plain.CopyTo(cs);

                                    var buffer = new byte[kBbufferSize * 1024];
                                    int read;
                                    var percentageDone = 0;

                                    while ((read = sourceFs.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        cs.Write(buffer, 0, read);

                                        var tmpPercentageDone = (int)(sourceFs.Position * 100 / sourceFs.Length);

                                        if (tmpPercentageDone != percentageDone)
                                        {
                                            percentageDone = tmpPercentageDone;

                                            RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? $"Encrypting ({percentageDone}%)..." : $"Encrypted ({percentageDone}%)."));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(sourceFilePath);
                    File.Move(encryptedFilePath + "_tmpcrypt", encryptedFilePath);
                }

                if (deleteSourceFile && !pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(sourceFilePath);
                }

                //var message = $"File \"{sourceFilePath}\" successfully encrypted to \"{encryptedFilePath}\".";
                var message = string.Format(MessageStrings.Encryption_FileEncryptSuccess, sourceFilePath, encryptedFilePath);
                message += (deleteSourceFile && !pathsEqual ? $"\n{string.Format(MessageStrings.Encryption_FileDeleted, sourceFilePath)}" : "");

                return new AesEncryptionResult()
                {
                    Success = true,
                    Message = message,
                    Key = _key,
                    IV = _IV,
                    AesCipherMode = (AesCipherMode)cipherMode,
                    PaddingMode = paddingMode
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Encryption_ExceptionError}\n{ex.ToString()}"
                };
            }
        }

        internal AesDecryptionResult DecryptWithFileStream(string encryptedFilePath, string decryptedFilePath, byte[] key, byte[] IV, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7, bool deleteEncryptedFile = false, int kBbufferSize = 4, long startPosition = 0, long endPosition = 0)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Decryption_EncryptedFileNotFound} \"{encryptedFilePath}\"."
                };
            }

            if (string.IsNullOrWhiteSpace(decryptedFilePath))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_DecryptedFilePathError
                };
            }

            var destinationDirectory = Path.GetDirectoryName(decryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Encryption_DestinationDirectoryNotFound} \"{destinationDirectory}\"."
                };
            }

            _key = key ?? _key;
            _IV = IV ?? _IV;

            if (_key == null)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_NullKeyError
                };
            }

            if (_IV == null)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_NullIVError
                };
            }

            if (endPosition < startPosition)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = string.Format(MessageStrings.Decryption_EndPositionLessThanStartError, endPosition, startPosition)
                };
            }

            var pathsEqual = decryptedFilePath.Equals(encryptedFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    aesManaged.Key = _key;
                    aesManaged.IV = _IV;
                    aesManaged.Mode = cipherMode;
                    aesManaged.Padding = paddingMode;

                    using (var decryptedFs = File.Open((pathsEqual ? decryptedFilePath + "_tmpdecrypt" : decryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        using (var encryptedFs = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            encryptedFs.Position = startPosition;

                            using (var decryptor = aesManaged.CreateDecryptor(_key, _IV))
                            {
                                using (var cs = new CryptoStream(decryptedFs, decryptor, CryptoStreamMode.Write))
                                {
                                    //encrypted.CopyTo(cs);

                                    var buffer = new byte[kBbufferSize * 1024];
                                    var totalBytesToRead = ((endPosition == 0 ? encryptedFs.Length : endPosition) - startPosition);
                                    var totalBytesNotRead = totalBytesToRead;
                                    long totalBytesRead = 0;
                                    var percentageDone = 0;

                                    while (totalBytesNotRead > 0)
                                    {
                                        var bytesRead = encryptedFs.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                                        if (bytesRead > 0)
                                        {
                                            cs.Write(buffer, 0, bytesRead);

                                            totalBytesRead += bytesRead;
                                            totalBytesNotRead -= bytesRead;
                                            var tmpPercentageDone = (int)(totalBytesRead * 100 / totalBytesToRead);

                                            if (tmpPercentageDone != percentageDone)
                                            {
                                                percentageDone = tmpPercentageDone;

                                                RaiseOnDecryptionProgress(percentageDone, (percentageDone != 100 ? $"Decrypting ({percentageDone}%)..." : $"Decrypted ({percentageDone}%)."));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(encryptedFilePath);
                    File.Move(decryptedFilePath + "_tmpdecrypt", decryptedFilePath);
                }

                if (deleteEncryptedFile && !pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(encryptedFilePath);
                }

                var message = string.Format(MessageStrings.Decryption_FileDecryptSuccess, encryptedFilePath, decryptedFilePath);
                message += (deleteEncryptedFile && !pathsEqual ? $"\n{string.Format(MessageStrings.Encryption_FileDeleted, encryptedFilePath)}" : "");

                return new AesDecryptionResult()
                {
                    Success = true,
                    Message = message,
                    Key = _key,
                    IV = _IV,
                    AesCipherMode = (AesCipherMode)cipherMode,
                    PaddingMode = paddingMode
                };
            }
            catch (Exception ex)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Decryption_ExceptionError}\n{ex.ToString()}"
                };
            }
        }

        #endregion internal methods


        #region private methods

        internal void RaiseOnEncryptionMessage(string message)
        {
            OnEncryptionMessage?.Invoke(message);
        }

        internal void RaiseOnDecryptionMessage(string message)
        {
            OnDecryptionMessage?.Invoke(message);
        }

        internal void RaiseOnEncryptionProgress(int percentageDone, string message)
        {
            OnEncryptionProgress?.Invoke(percentageDone, message);
        }

        internal void RaiseOnDecryptionProgress(int percentageDone, string message)
        {
            OnDecryptionProgress?.Invoke(percentageDone, message);
        }

        #endregion private methods
    }
}
