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

namespace CryptHash.Net.Hash.Base
{
    public abstract class HashBase
    {
        public event OnHashProgressHandler OnHashProgress;


        internal GenericHashResult ComputeHash(Enums.HashAlgorithm hashAlgorithm, byte[] bytesToComputeHash)
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
                using (var hashAlg = System.Security.Cryptography.HashAlgorithm.Create(hashAlgorithm.ToString()))
                {
                    byte[] hash = hashAlg.ComputeHash(bytesToComputeHash);

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = MessageDictionary.Instance["Hash.Compute.Success"],
                        HashBytes = hash
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

        internal GenericHashResult ComputeHash(Enums.HashAlgorithm hashAlgorithm, string stringToComputeHash)
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
            var result = ComputeHash(hashAlgorithm, stringToComputeHashBytes);

            if (result.Success)
                result.HashString = CommonMethods.ConvertByteArrayToHexString(result.HashBytes);

            return result;
        }

        internal GenericHashResult ComputeFileHash(Enums.HashAlgorithm hashAlgorithm, string filePathToComputeHash)
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
                    var startPosition = 0;
                    var endPosition = fStream.Length;
                    fStream.Position = startPosition;
                    byte[] buffer = new byte[(1024 * 4)];
                    long amount = (endPosition - startPosition);

                    using (var hashAlg = System.Security.Cryptography.HashAlgorithm.Create(hashAlgorithm.ToString()))
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

                                var tmpPercentageDone = (int)(fStream.Position * 100 / endPosition);

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

        internal GenericHashResult VerifyHash(Enums.HashAlgorithm hashAlgorithm, byte[] hashBytes, byte[] bytesToVerifyHash)
        {
            var hashResult = ComputeHash(hashAlgorithm, bytesToVerifyHash);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(hashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}";
            }

            return hashResult;
        }

        internal GenericHashResult VerifyHash(Enums.HashAlgorithm hashAlgorithm, string hashHexString, string stringToVerifyHash)
        {
            var hashBytes = CommonMethods.ConvertHexStringToByteArray(hashHexString);
            var stringToVerifyHashBytes = Encoding.UTF8.GetBytes(stringToVerifyHash);

            return VerifyHash(hashAlgorithm, hashBytes, stringToVerifyHashBytes);
        }

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, string hashHexString, string filePathToVerifyHash)
        {
            var hashBytes = CommonMethods.ConvertHexStringToByteArray(hashHexString);

            return VerifyFileHash(hashAlgorithm, hashBytes, filePathToVerifyHash);
        }

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, byte[] hashBytes, string filePathToVerifyHash)
        {
            var hashResult = ComputeFileHash(hashAlgorithm, filePathToVerifyHash);

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
