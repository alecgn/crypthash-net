﻿/*
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

            string hashAlgorithmName;

            switch (hashAlgorithm)
            {
                case Enums.HashAlgorithm.MD5:
                    {
                        hashAlgorithmName = "MD5";
                    }
                    break;
                case Enums.HashAlgorithm.SHA1:
                    {
                        hashAlgorithmName = "SHA1";
                    }
                    break;
                case Enums.HashAlgorithm.SHA256:
                    {
                        hashAlgorithmName = "SHA256";
                    }
                    break;
                case Enums.HashAlgorithm.SHA384:
                    {
                        hashAlgorithmName = "SHA384";
                    }
                    break;
                case Enums.HashAlgorithm.SHA512:
                    {
                        hashAlgorithmName = "SHA512";
                    }
                    break;
                case Enums.HashAlgorithm.BCrypt:
                default:
                    {
                        return new GenericHashResult()
                        {
                            Success = false,
                            Message = $"{MessageDictionary.Instance["Common.AlgorithmNotSupported"]} \"{hashAlgorithm.ToString()}\"."
                        };
                    }
            }

            GenericHashResult result = null;

            try
            {
                using (var hashAlg = System.Security.Cryptography.HashAlgorithm.Create(hashAlgorithmName))
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

            var bytesToBeHashed = Encoding.UTF8.GetBytes(stringToComputeHash);
            var result = ComputeHash(hashAlgorithm, bytesToBeHashed);

            if (result.Success)
                result.HashString = CommonMethods.ConvertByteArrayToHexString(result.HashBytes);

            return result;
        }

        internal GenericHashResult ComputeFileHash(Enums.HashAlgorithm hashAlgorithm, string sourceFilePath)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.FileNotFound"]} \"{sourceFilePath}\"."
                };
            }

            string hashAlgorithmName;

            switch (hashAlgorithm)
            {
                case Enums.HashAlgorithm.MD5:
                    {
                        hashAlgorithmName = "MD5";
                    }
                    break;
                case Enums.HashAlgorithm.SHA1:
                    {
                        hashAlgorithmName = "SHA1";
                    }
                    break;
                case Enums.HashAlgorithm.SHA256:
                    {
                        hashAlgorithmName = "SHA256";
                    }
                    break;
                case Enums.HashAlgorithm.SHA384:
                    {
                        hashAlgorithmName = "SHA384";
                    }
                    break;
                case Enums.HashAlgorithm.SHA512:
                    {
                        hashAlgorithmName = "SHA512";
                    }
                    break;
                case Enums.HashAlgorithm.BCrypt:
                default:
                    {
                        return new GenericHashResult()
                        {
                            Success = false,
                            Message = $"{MessageDictionary.Instance["Common.AlgorithmNotSupported"]} \"{hashAlgorithm.ToString()}\"."
                        };
                    }
            }

            GenericHashResult result = null;

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

                    using (var hashAlg = System.Security.Cryptography.HashAlgorithm.Create(hashAlgorithmName))
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

        internal GenericHashResult VerifyHash(Enums.HashAlgorithm hashAlgorithm, string base64HashString, string stringToVerifyHash)
        {
            var hashBytes = Convert.FromBase64String(base64HashString);
            var stringToVerifyHashBytes = Encoding.UTF8.GetBytes(stringToVerifyHash);

            return VerifyHash(hashAlgorithm, hashBytes, stringToVerifyHashBytes);
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

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, string base64HashString, string sourceFilePath)
        {
            var hashBytes = Convert.FromBase64String(base64HashString);

            return VerifyFileHash(hashAlgorithm, hashBytes, sourceFilePath);
        }

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, byte[] hashBytes, string sourceFilePath)
        {
            var hashResult = ComputeFileHash(hashAlgorithm, sourceFilePath);

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