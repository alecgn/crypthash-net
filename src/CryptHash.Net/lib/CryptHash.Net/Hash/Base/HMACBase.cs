/*
 *      Alessandro Cagliostro, 2020
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
    public abstract class HMACBase
    {
        public event OnHashProgressHandler OnHashProgress;


        internal HMACHashResult ComputeHMAC(Enums.HMACAlgorithm hmacAlgorithm, byte[] bytesToComputeHMAC, byte[] key = null,
            int offset = 0, int count = 0)
        {
            if (bytesToComputeHMAC == null || bytesToComputeHMAC.Length <= 0)
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["HMAC.InputRequired"]
                };
            }

            if (key == null || key.Length == 0)
                key = CommonMethods.GenerateRandomBytes(HMACOutputLengthDictionary.Instance[hmacAlgorithm] / 8);

            HMACHashResult result = null;

            try
            {
                using (var hmac = (HMAC)CryptoConfig.CreateFromName(hmacAlgorithm.ToString()))
                {
                    hmac.Key = key;
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? bytesToComputeHMAC.Length : count);

                    byte[] hash = hmac.ComputeHash(bytesToComputeHMAC, offset, count);

                    result = new HMACHashResult()
                    {
                        Success = true,
                        Message = MessageDictionary.Instance["HMAC.ComputeSuccess"],
                        HashBytes = hash,
                        HashString = Encoding.HighPerformanceHexadecimal.ToHexString(hash),
                        Key = key,
                        PRF = hmacAlgorithm
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

        internal HMACHashResult ComputeHMAC(Enums.HMACAlgorithm hmacAlgorithm, string stringToComputeHMAC, byte[] key = null,
            int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHMAC))
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["HMAC.InputRequired"]
                };
            }

            var stringToComputeHMACBytes = System.Text.Encoding.UTF8.GetBytes(stringToComputeHMAC);
            
            return ComputeHMAC(hmacAlgorithm, stringToComputeHMACBytes, key, offset, count);
        }

        internal HMACHashResult ComputeFileHMAC(Enums.HMACAlgorithm hmacAlgorithm, string filePathToComputeHMAC, byte[] key = null, 
            long offset = 0, long count = 0)
        {
            if (!File.Exists(filePathToComputeHMAC))
            {
                return new HMACHashResult()
                {
                    Success = false,
                    Message = $"{MessageDictionary.Instance["Common.FileNotFound"]} \"{filePathToComputeHMAC}\"."
                };
            }

            if (key == null || key.Length == 0)
                key = CommonMethods.GenerateRandomBytes(HMACOutputLengthDictionary.Instance[hmacAlgorithm] / 8);

            HMACHashResult result = null;

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? fStream.Length : count);
                    fStream.Position = offset;
                    byte[] buffer = new byte[(1024 * 4)];
                    long amount = (count - offset);

                    using (var hmac = (HMAC)CryptoConfig.CreateFromName(hmacAlgorithm.ToString()))
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

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

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
                    HashString = Encoding.HighPerformanceHexadecimal.ToHexString(hash),
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


        internal HMACHashResult VerifyHMAC(Enums.HMACAlgorithm hmacAlgorithm, byte[] hmacBytes, byte[] bytesToVerifyHMAC, byte[] key,
            int offset = 0, int count = 0)
        {
            var hmacResult = ComputeHMAC(hmacAlgorithm, bytesToVerifyHMAC, key, offset, count);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}";
            }

            return hmacResult;
        }

        internal HMACHashResult VerifyHMAC(Enums.HMACAlgorithm hmacAlgorithm, string hmacHexString, string stringToVerifyHMAC, byte[] key,
            int offset = 0, int count = 0)
        {
            var hmacBytes = Encoding.HighPerformanceHexadecimal.ToByteArray(hmacHexString);
            var stringToVerifyHMACBytes = System.Text.Encoding.UTF8.GetBytes(stringToVerifyHMAC);

            return VerifyHMAC(hmacAlgorithm, hmacBytes, stringToVerifyHMACBytes, key, offset, count);
        }

        internal HMACHashResult VerifyFileHMAC(Enums.HMACAlgorithm hmacAlgorithm, string hmacHexString, string filePathToVerifyHMAC, byte[] key,
            long offset = 0, long count = 0)
        {
            var hmacBytes = Encoding.HighPerformanceHexadecimal.ToByteArray(hmacHexString);

            return VerifyFileHMAC(hmacAlgorithm, hmacBytes, filePathToVerifyHMAC, key, offset, count);
        }

        internal HMACHashResult VerifyFileHMAC(Enums.HMACAlgorithm hmacAlgorithm, byte[] hmacBytes, string filePathToVerifyHMAC, byte[] key,
            long offset = 0, long count = 0)
        {
            var hmacResult = ComputeFileHMAC(hmacAlgorithm, filePathToVerifyHMAC, key, offset, count);

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
