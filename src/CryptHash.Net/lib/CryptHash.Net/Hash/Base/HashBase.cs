/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Text;
using CryptHash.Net.Util;
using CryptHash.Net.Util.EventHandlers;
using CryptHash.Net.Hash.HashResults;
using System.Linq;
using System.Security.Cryptography;

namespace CryptHash.Net.Hash.Base
{
    public abstract class HashBase
    {
        public event OnHashProgressHandler OnHashProgress;


        internal GenericHashResult ComputeHash(Enums.HashAlgorithm hashAlgorithm, byte[] bytesToComputeHash,
            int offset = 0, int count = 0)
        {
            if (bytesToComputeHash == null || bytesToComputeHash.Length <= 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Hash.InputRequired"]
                };
            }

            GenericHashResult result = null;

            try
            {
                using (var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithm.ToString()))
                {
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? bytesToComputeHash.Length : count);

                    byte[] hash = hashAlg.ComputeHash(bytesToComputeHash, offset, count);

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = MessageDictionary.Instance["Hash.Compute.Success"],
                        HashBytes = hash,
                        HashString = CommonMethods.ConvertByteArrayToHexString(hash)
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

        internal GenericHashResult ComputeHash(Enums.HashAlgorithm hashAlgorithm, string stringToComputeHash,
            int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Hash.InputRequired"]
                };
            }

            var stringToComputeHashBytes = Encoding.UTF8.GetBytes(stringToComputeHash);
            
            return ComputeHash(hashAlgorithm, stringToComputeHashBytes, offset, count);
        }

        internal GenericHashResult ComputeFileHash(Enums.HashAlgorithm hashAlgorithm, string filePathToComputeHash, 
            long offset = 0, long count = 0)
        {
            if (!File.Exists(filePathToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.FileNotFound"]} \"{filePathToComputeHash}\"."
                };
            }

            GenericHashResult result = null;

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(filePathToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? fStream.Length : count);
                    fStream.Position = offset;
                    byte[] buffer = new byte[(1024 * 4)];
                    long amount = (count - offset);

                    using (var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithm.ToString()))
                    {
                        int percentageDone = 0;

                        while (amount > 0)
                        {
                            int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                    hashAlg.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                else
                                    hashAlg.TransformFinalBlock(buffer, 0, bytesRead);

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgress(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
                                }
                            }
                            else
                                throw new InvalidOperationException();
                        }

                        hash = hashAlg.Hash;
                    }
                }

                result = new GenericHashResult()
                {
                    Success = true,
                    Message = MessageDictionary.Instance["Hash.ComputeSuccess"],
                    HashString = CommonMethods.ConvertByteArrayToHexString(hash),
                    HashBytes = hash
                };
            }
            catch (Exception ex)
            {
                result = new GenericHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }


        internal GenericHashResult VerifyHash(Enums.HashAlgorithm hashAlgorithm, byte[] hashBytes, byte[] bytesToVerifyHash,
            int offset = 0, int count = 0)
        {
            var hashResult = ComputeHash(hashAlgorithm, bytesToVerifyHash, offset, count);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(hashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}";
            }

            return hashResult;
        }

        internal GenericHashResult VerifyHash(Enums.HashAlgorithm hashAlgorithm, string hashHexString, string stringToVerifyHash,
            int offset = 0, int count = 0)
        {
            var hashBytes = CommonMethods.ConvertHexStringToByteArray(hashHexString);
            var stringToVerifyHashBytes = Encoding.UTF8.GetBytes(stringToVerifyHash);

            return VerifyHash(hashAlgorithm, hashBytes, stringToVerifyHashBytes, offset, count);
        }

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, string hashHexString, string filePathToVerifyHash,
            long offset = 0, long count = 0)
        {
            var hashBytes = CommonMethods.ConvertHexStringToByteArray(hashHexString);

            return VerifyFileHash(hashAlgorithm, hashBytes, filePathToVerifyHash, offset, count);
        }

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, byte[] hashBytes, string filePathToVerifyHash,
            long offset = 0, long count = 0)
        {
            var hashResult = ComputeFileHash(hashAlgorithm, filePathToVerifyHash, offset, count);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(hashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}";
            }

            return hashResult;
        }

        internal void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}
