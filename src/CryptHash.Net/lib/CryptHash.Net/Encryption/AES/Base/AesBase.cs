/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Security.Cryptography;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Encryption.Utils.EventHandlers;

namespace CryptHash.Net.Encryption.AES.Base
{
    public abstract class AesBase
    {
        #region events

        public event OnEncryptionMessageHandler OnEncryptionMessage;

        public event OnEncryptionProgressHandler OnEncryptionProgress;

        #endregion events


        #region fields

        private byte[] _key;
        private byte[] _IV;
        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;

        #endregion fields


        #region constructors

        internal AesBase() { }

        internal AesBase(byte[] key, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode)
        {
            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
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
                    Message = "Source data cannot be null or 0 bytes."
                };
            }

            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;

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
                    {
                        if (aesManaged.ValidKeySize((_key.Length * 8)))
                            aesManaged.Key = _key;
                        else
                        {
                            return new AesEncryptionResult()
                            {
                                Success = false,
                                Message = $"Invalid key bit size ({(_key.Length * 8)})."
                            };
                        }
                    }

                    if (_IV == null)
                    {
                        aesManaged.GenerateIV();
                        _IV = aesManaged.IV;
                    }
                    else
                        aesManaged.IV = _IV;

                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;

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
                IV = _IV,
                CipherMode = _cipherMode,
                PaddingMode = _paddingMode
            };
        }

        internal AesEncryptionResult DecryptWithMemoryStream(byte[] encryptedData, byte[] key, byte[] IV, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Encrypted data cannot be null or 0 bytes."
                };
            }

            if (key == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Key cannot be null."
                };
            }

            if (IV == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "IV cannot be null."
                };
            }

            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;

            byte[] decryptedData = null;

            try
            {
                using (AesManaged aesManaged = new AesManaged())
                {
                    if (aesManaged.ValidKeySize((_key.Length * 8)))
                        aesManaged.Key = _key;
                    else
                    {
                        return new AesEncryptionResult()
                        {
                            Success = false,
                            Message = $"Invalid key bit size ({(_key.Length * 8)})."
                        };
                    }

                    aesManaged.IV = _IV;
                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;

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
                IV = _IV,
                CipherMode = _cipherMode,
                PaddingMode = _paddingMode
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

            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;

            bool pathsEqual = encryptedFilePath.Equals(sourceFilePath, StringComparison.InvariantCultureIgnoreCase);

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
                            aesManaged.Key = _key;
                        else
                        {
                            return new AesEncryptionResult()
                            {
                                Success = false,
                                Message = $"Invalid key bit size ({(_key.Length * 8)})."
                            };
                        }
                    }

                    if (_IV == null || _IV.Length == 0)
                    {
                        aesManaged.GenerateIV();
                        _IV = aesManaged.IV;
                    }
                    else
                        aesManaged.IV = _IV;

                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;

                    using (var encryptor = aesManaged.CreateEncryptor(_key, _IV))
                    {
                        using (FileStream sourceFs = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            using (FileStream encryptedFs = File.Open((pathsEqual ? encryptedFilePath + "_tmpcrypt" : encryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                using (CryptoStream cs = new CryptoStream(encryptedFs, encryptor, CryptoStreamMode.Write))
                                {
                                    //plain.CopyTo(cs);

                                    byte[] buffer = new byte[kBbufferSize * 1024];
                                    int read;
                                    int percentageDone = 0;

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
                    Utils.EncryptionUtils.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(sourceFilePath);
                    File.Move(encryptedFilePath + "_tmpcrypt", encryptedFilePath);
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
                    IV = _IV,
                    CipherMode = _cipherMode,
                    PaddingMode = _paddingMode
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

        internal AesEncryptionResult DecryptWithFileStream(string encryptedFilePath, string decryptedFilePath, byte[] key, byte[] IV, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7, bool deleteEncryptedFile = false, int kBbufferSize = 4, long startPosition = 0, long endPosition = 0)
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

            if (key == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "Key cannot be null."
                };
            }

            if (IV == null)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = "IV cannot be null."
                };
            }

            if (endPosition < startPosition)
            {
                return new AesEncryptionResult()
                {
                    Success = false,
                    Message = $"End position (\"{endPosition}\") cannot be less than start position (\"{startPosition}\")."
                };
            }

            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;

            bool pathsEqual = decryptedFilePath.Equals(encryptedFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    aesManaged.Key = _key;
                    aesManaged.IV = _IV;
                    aesManaged.Mode = _cipherMode;
                    aesManaged.Padding = _paddingMode;

                    using (FileStream decryptedFs = File.Open((pathsEqual ? decryptedFilePath + "_tmpdecrypt" : decryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        using (FileStream encryptedFs = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            encryptedFs.Position = startPosition;

                            using (var decryptor = aesManaged.CreateDecryptor(_key, _IV))
                            {
                                using (CryptoStream cs = new CryptoStream(decryptedFs, decryptor, CryptoStreamMode.Write))
                                {
                                    //encrypted.CopyTo(cs);

                                    byte[] buffer = new byte[kBbufferSize * 1024];
                                    long totalBytesToRead = ((endPosition == 0 ? encryptedFs.Length : endPosition) - startPosition);
                                    long totalBytesNotRead = totalBytesToRead;
                                    long totalBytesRead = 0;
                                    int percentageDone = 0;

                                    while (totalBytesNotRead > 0)
                                    {
                                        int bytesRead = encryptedFs.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                                        if (bytesRead > 0)
                                        {
                                            cs.Write(buffer, 0, bytesRead);

                                            totalBytesRead += bytesRead;
                                            totalBytesNotRead -= bytesRead;
                                            var tmpPercentageDone = (int)(totalBytesRead * 100 / totalBytesToRead);

                                            if (tmpPercentageDone != percentageDone)
                                            {
                                                percentageDone = tmpPercentageDone;

                                                RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? $"Decrypting ({percentageDone}%)..." : $"Decrypted ({percentageDone}%)."));
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
                    Utils.EncryptionUtils.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid erros while trying to delete the file below
                    File.Delete(encryptedFilePath);
                    File.Move(decryptedFilePath + "_tmpdecrypt", decryptedFilePath);
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
                    IV = _IV,
                    CipherMode = _cipherMode,
                    PaddingMode = _paddingMode
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

        #endregion internal methods


        #region private methods

        internal void RaiseOnEncryptionMessage(string message)
        {
            OnEncryptionMessage?.Invoke(message);
        }

        internal void RaiseOnEncryptionProgress(int percentageDone, string message)
        {
            OnEncryptionProgress?.Invoke(percentageDone, message);
        }

        #endregion private methods
    }
}
