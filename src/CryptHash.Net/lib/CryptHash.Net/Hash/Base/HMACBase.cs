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
    public abstract class HMACBase
    {
        public event OnHashProgressHandler OnHashProgress;


        internal HMACHashResult ComputeHMAC(Enums.HMACAlgorithm hmacAlgorithm, byte[] bytesToComputeHMAC, byte[] key = null)
        {
            if (bytesToComputeHMAC == null || bytesToComputeHMAC.Length <= 0)
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["HMAC.InputRequired"]
                };
            }

            if (key != null && key.Length != HMACOutputLengthDictionary.Instance[hmacAlgorithm])
            {
                //throw new ArgumentException($"Key size invalid for algorithm {hashAlgorithmHMACName}.", nameof(key));
                return new HMACHashResult() {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.InvalidKeySizeError"]} ({key.Length})."
                };
            }

            if (key == null)
                key = CommonMethods.GenerateRandomBytes(HMACOutputLengthDictionary.Instance[hmacAlgorithm] / 8);

            HMACHashResult result = null;

            try
            {
                using (var hmac = System.Security.Cryptography.HMAC.Create(hmacAlgorithm.ToString()))
                {
                    hmac.Key = key;
                    byte[] hash = hmac.ComputeHash(bytesToComputeHMAC);

                    result = new HMACHashResult()
                    {
                        Success = true,
                        Message = MessageDictionary.Instance["HMAC.ComputeSuccess"],
                        HashBytes = hash,
                        Key = key
                    };
                }
            }
            catch (Exception ex)
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }

        internal HMACHashResult ComputeHMAC(Enums.HMACAlgorithm hmacAlgorithm, string stringToComputeHMAC, byte[] key = null)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHMAC))
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["HMAC.InputRequired"]
                };
            }

            var bytesToBeHashed = Encoding.UTF8.GetBytes(stringToComputeHMAC);
            var result = ComputeHMAC(hmacAlgorithm, bytesToBeHashed, key);

            if (result.Success)
                result.HashString = CommonMethods.ConvertByteArrayToHexString(result.HashBytes);

            return result;
        }

        internal HMACHashResult ComputeFileHMAC(Enums.HMACAlgorithm hmacAlgorithm, string filePathToComputeHMAC, byte[] key = null)
        {
            if (!File.Exists(filePathToComputeHMAC))
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.FileNotFound"]} \"{filePathToComputeHMAC}\"."
                };
            }

            if (key != null && key.Length != HMACOutputLengthDictionary.Instance[hmacAlgorithm])
            {
                //throw new ArgumentException($"Key size invalid for algorithm {hashAlgorithmName}.", nameof(key));
                return new HMACHashResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.InvalidKeySizeError"]} ({key.Length})."
                };
            }

            if (key == null)
                key = CommonMethods.GenerateRandomBytes(HMACOutputLengthDictionary.Instance[hmacAlgorithm] / 8);

            HMACHashResult result = null;

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var startPosition = 0;
                    var endPosition = fStream.Length;
                    fStream.Position = startPosition;
                    byte[] buffer = new byte[(1024 * 4)];
                    long amount = (endPosition - startPosition);

                    using (var hmac = System.Security.Cryptography.HMAC.Create(hmacAlgorithm.ToString()))
                    {
                        hmac.Key = key;
                        int percentageDone = 0;

                        while (amount > 0)
                        {
                            int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                    hmac.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                else
                                    hmac.TransformFinalBlock(buffer, 0, bytesRead);

                                var tmpPercentageDone = (int)(fStream.Position * 100 / endPosition);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgress(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
                                }
                            }
                            else
                                throw new InvalidOperationException();
                        }

                        hash = hmac.Hash;
                    }
                }

                result = new HMACHashResult()
                {
                    Success = true,
                    Message = MessageDictionary.Instance["HMAC.ComputeSuccess"],
                    HashString = CommonMethods.ConvertByteArrayToHexString(hash),
                    HashBytes = hash,
                    Key = key
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

        internal HMACHashResult VerifyHMAC(Enums.HMACAlgorithm hmacAlgorithm, byte[] hmacBytes, byte[] bytesToVerifyHMAC, byte[] key)
        {
            var hmacResult = ComputeHMAC(hmacAlgorithm, bytesToVerifyHMAC, key);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}";
            }

            return hmacResult;
        }

        internal HMACHashResult VerifyHMAC(Enums.HMACAlgorithm hmacAlgorithm, string base64HMACString, string stringToVerifyHMAC, byte[] key)
        {
            var hmacBytes = Convert.FromBase64String(base64HMACString);
            var stringToVerifyHMACBytes = Encoding.UTF8.GetBytes(stringToVerifyHMAC);

            return VerifyHMAC(hmacAlgorithm, hmacBytes, stringToVerifyHMACBytes, key);
        }

        internal HMACHashResult VerifyFileHMAC(Enums.HMACAlgorithm hmacAlgorithm, string base64HMACString, string filePathToVerifyHMAC, byte[] key)
        {
            var hmacBytes = Convert.FromBase64String(base64HMACString);

            return VerifyFileHMAC(hmacAlgorithm, hmacBytes, filePathToVerifyHMAC, key);
        }

        internal HMACHashResult VerifyFileHMAC(Enums.HMACAlgorithm hmacAlgorithm, byte[] hmacBytes, string filePathToVerifyHMAC, byte[] key)
        {
            var hmacResult = ComputeFileHMAC(hmacAlgorithm, filePathToVerifyHMAC, key);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}";
            }

            return hmacResult;
        }

        internal void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}
