/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using
/* Unmerged change from project 'CryptHash.Net (netstandard2.1)'
Before:
using System.IO;
using System.Text;
After:
using System.Net.Hash.HashResults;
*/
CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Resources;
using CryptHash.Net.Util.EventHandlers;
using System;
using System.IO;
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
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            GenericHashResult result = null;

            try
            {
                HashAlgorithm hashAlg = null;

#if CORERT
                switch (hashAlgorithm)
                {
                    case Enums.HashAlgorithm.MD5:
                        hashAlg = MD5.Create();
                        break;
                    case Enums.HashAlgorithm.SHA1:
                        hashAlg = SHA1.Create();
                        break;
                    case Enums.HashAlgorithm.SHA256:
                        hashAlg = SHA256.Create();
                        break;
                    case Enums.HashAlgorithm.SHA384:
                        hashAlg = SHA384.Create();
                        break;
                    case Enums.HashAlgorithm.SHA512:
                        hashAlg = SHA512.Create();
                        break;
                    case Enums.HashAlgorithm.BCrypt:
                    default:
                        break;
                }

#else
                hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithm.ToString());
#endif

                using (hashAlg)
                {
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? bytesToComputeHash.Length : count);

                    var hash = hashAlg.ComputeHash(bytesToComputeHash, offset, count);

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = MessageStrings.Hash_ComputeSuccess,
                        HashBytes = hash,
                        HashString = Encoding.HighPerformanceHexadecimal.ToHexString(hash)
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
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            var stringToComputeHashBytes = System.Text.Encoding.UTF8.GetBytes(stringToComputeHash);

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
                    Message = $"{MessageStrings.Common_FileNotFound} \"{filePathToComputeHash}\"."
                };
            }

            GenericHashResult result = null;
            HashAlgorithm hashAlg = null;

#if CORERT
            switch (hashAlgorithm)
            {
                case Enums.HashAlgorithm.MD5:
                    hashAlg = MD5.Create();
                    break;
                case Enums.HashAlgorithm.SHA1:
                    hashAlg = SHA1.Create();
                    break;
                case Enums.HashAlgorithm.SHA256:
                    hashAlg = SHA256.Create();
                    break;
                case Enums.HashAlgorithm.SHA384:
                    hashAlg = SHA384.Create();
                    break;
                case Enums.HashAlgorithm.SHA512:
                    hashAlg = SHA512.Create();
                    break;
                case Enums.HashAlgorithm.BCrypt:
                default:
                    break;
            }
#else
            hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithm.ToString());
#endif

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(filePathToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? fStream.Length : count);
                    fStream.Position = offset;
                    var buffer = new byte[(1024 * 4)];
                    var amount = (count - offset);

                    using (hashAlg)
                    {
                        var percentageDone = 0;

                        while (amount > 0)
                        {
                            var bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                {
                                    hashAlg.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                }
                                else
                                {
                                    hashAlg.TransformFinalBlock(buffer, 0, bytesRead);
                                }

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgress(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
                                }
                            }
                            else
                            {
                                throw new InvalidOperationException();
                            }
                        }

                        hash = hashAlg.Hash;
                    }
                }

                result = new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashString = Encoding.HighPerformanceHexadecimal.ToHexString(hash),
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
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        internal GenericHashResult VerifyHash(Enums.HashAlgorithm hashAlgorithm, string hashHexString, string stringToVerifyHash,
            int offset = 0, int count = 0)
        {
            var hashBytes = Encoding.HighPerformanceHexadecimal.ToByteArray(hashHexString);
            var stringToVerifyHashBytes = System.Text.Encoding.UTF8.GetBytes(stringToVerifyHash);

            return VerifyHash(hashAlgorithm, hashBytes, stringToVerifyHashBytes, offset, count);
        }

        internal GenericHashResult VerifyFileHash(Enums.HashAlgorithm hashAlgorithm, string hashHexString, string filePathToVerifyHash,
            long offset = 0, long count = 0)
        {
            var hashBytes = Encoding.HighPerformanceHexadecimal.ToByteArray(hashHexString);

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
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        internal void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}
