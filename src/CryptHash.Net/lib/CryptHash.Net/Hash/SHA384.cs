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
    public class SHA384
    {
        public event OnHashProgressHandler OnHashProgress;


        public GenericHashResult HashString(string stringToBeHashed)
        {
            if (string.IsNullOrWhiteSpace(stringToBeHashed))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "String to be hashed required."
                };
            }

            StringBuilder sb = null;
            GenericHashResult result = null;

            try
            {
                using (var sha384 = SHA384Managed.Create())
                {
                    byte[] stringToBeHashedBytes = Encoding.UTF8.GetBytes(stringToBeHashed);
                    byte[] hashedBytes = sha384.ComputeHash(stringToBeHashedBytes);


                    sb = new StringBuilder();

                    for (int i = 0; i < hashedBytes.Length; i++)
                    {
                        sb.Append(hashedBytes[i].ToString("X2"));
                    }

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = "String succesfully hashed.",
                        HashString = sb.ToString(),
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
            finally
            {
                sb.Clear();
                sb = null;
            }

            return result;
        }

        //public GenericHashResult HashFile(string sourceFilePath, bool verbose = false)
        //{
        //    if (!File.Exists(sourceFilePath))
        //    {
        //        return new GenericHashResult()
        //        {
        //            Success = false,
        //            Message = $"File \"{sourceFilePath}\" not found."
        //        };
        //    }

        //    StringBuilder sb = null;
        //    GenericHashResult result = null;

        //    try
        //    {
        //        using (var sha384 = SHA384Managed.Create())
        //        {
        //            using (var fs = File.OpenRead(sourceFilePath))
        //            {
        //                sb = new StringBuilder();
        //                var hashedBytes = sha384.ComputeHash(fs);

        //                for (int i = 0; i < hashedBytes.Length; i++)
        //                {
        //                    sb.Append(hashedBytes[i].ToString("X2"));
        //                }

        //                result = new GenericHashResult()
        //                {
        //                    Success = true,
        //                    Message = $"File \"{sourceFilePath}\" succesfully hashed.",
        //                    HashString = sb.ToString()
        //                };
        //            }
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        return new GenericHashResult()
        //        {
        //            Success = false,
        //            Message = ex.ToString()
        //        };
        //    }
        //    finally
        //    {
        //        sb.Clear();
        //        sb = null;
        //    }

        //    return result;
        //}

        public GenericHashResult HashFile(string sourceFilePath)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"File \"{sourceFilePath}\" not found."
                };
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

                    using (var sha384 = System.Security.Cryptography.SHA384Managed.Create())
                    {
                        int percentageDone = 0;

                        while (amount > 0)
                        {
                            int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                    sha384.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                else
                                    sha384.TransformFinalBlock(buffer, 0, bytesRead);

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

                        hash = sha384.Hash;
                    }
                }

                result = new GenericHashResult()
                {
                    Success = true,
                    Message = $"File \"{sourceFilePath}\" succesfully hashed.",
                    HashString = EncryptionUtils.ConvertByteArrayToHexString(hash),
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

        private void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}
