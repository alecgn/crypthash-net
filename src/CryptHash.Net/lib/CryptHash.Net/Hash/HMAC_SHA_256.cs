/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CryptHash.Net.Encryption.Utils;
using CryptHash.Net.Encryption.Utils.EventHandlers;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash
{
    public class HMAC_SHA_256
    {
        public event OnHashProgressHandler OnHashProgress;


        public GenericHashResult HashBytes(byte[] bytesToBeHashed, byte[] key = null)
        {
            if (bytesToBeHashed == null || bytesToBeHashed.Length <= 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "Bytes to be hashed required."
                };
            }

            if (key == null || key.Length <= 0)
                key = EncryptionUtils.GenerateRandomBytes(256 / 8);

            GenericHashResult result = null;

            try
            {
                using (var hmacSha256 = HMACSHA256.Create())
                {
                    hmacSha256.Key = key;
                    byte[] hashedBytes = hmacSha256.ComputeHash(bytesToBeHashed);

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = "String succesfully hashed.",
                        HashBytes = hashedBytes
                    };
                }
            }
            catch (Exception ex)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }

        public GenericHashResult HashString(string stringToBeHashed, byte[] key = null)
        {
            if (string.IsNullOrWhiteSpace(stringToBeHashed))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "String to be hashed required."
                };
            }

            if (key == null || key.Length <= 0)
                key = EncryptionUtils.GenerateRandomBytes(256/8);

            var bytesToBeHashed = Encoding.UTF8.GetBytes(stringToBeHashed);
            var result = HashBytes(bytesToBeHashed, key);

            if (result.Success)
                result.HashString = EncryptionUtils.ConvertByteArrayToHexString(result.HashBytes);

            return result;
        }

        public HMACHashResult HashFile(string sourceFilePath, byte[] key = null)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = $"File \"{sourceFilePath}\" not found."
                };
            }

            if (key == null || key.Length <= 0)
                key = EncryptionUtils.GenerateRandomBytes(256 / 8);

            HMACHashResult result = null;

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var startPosition = 0;
                    var endPosition = fStream.Length;
                    fStream.Position = startPosition;
                    byte[] buffer = new byte[(1024 * 4)];
                    long amount = (endPosition - startPosition);

                    using (var hmacSha256 = HMACSHA256.Create())
                    {
                        hmacSha256.Key = key;
                        int percentageDone = 0;

                        while (amount > 0)
                        {
                            int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                    hmacSha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                else
                                    hmacSha256.TransformFinalBlock(buffer, 0, bytesRead);

                                var tmpPercentageDone = (int)(fStream.Position * 100 / endPosition);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgress(percentageDone, (percentageDone != 100 ? $"Calculating hash ({percentageDone}%)..." : $"Hash calculated ({percentageDone}%)."));
                                }
                            }
                            else
                                throw new InvalidOperationException();
                        }

                        hash = hmacSha256.Hash;
                    }
                }

                result = new HMACHashResult()
                {
                    Success = true,
                    Message = $"File \"{sourceFilePath}\" succesfully hashed.",
                    HashString = EncryptionUtils.ConvertByteArrayToHexString(hash),
                    HashBytes = hash
                };
            }
            catch (Exception ex)
            {
                result = new HMACHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }

        private void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}
