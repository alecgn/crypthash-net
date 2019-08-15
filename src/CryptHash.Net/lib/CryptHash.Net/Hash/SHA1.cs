/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash
{
    public class SHA1
    {
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
                using (var sha1 = SHA1Managed.Create())
                {
                    byte[] stringToBeHashedBytes = Encoding.UTF8.GetBytes(stringToBeHashed);
                    byte[] hashedBytes = sha1.ComputeHash(stringToBeHashedBytes);

                    sb = new StringBuilder();

                    for (int i = 0; i < hashedBytes.Length; i++)
                    {
                        sb.Append(hashedBytes[i].ToString("X2"));
                    }

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = "String succesfully hashed.",
                        Hash = sb.ToString()
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

        public GenericHashResult HashFile(string sourceFilePath, bool verbose = false)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"File \"{sourceFilePath}\" not found."
                };
            }

            StringBuilder sb = null;
            GenericHashResult result = null;

            try
            {
                using (var sha1 = SHA1Managed.Create())
                {
                    using (var fs = File.OpenRead(sourceFilePath))
                    {
                        sb = new StringBuilder();
                        var hashedBytes = sha1.ComputeHash(fs);

                        for (int i = 0; i < hashedBytes.Length; i++)
                        {
                            sb.Append(hashedBytes[i].ToString("X2"));
                        }

                        result = new GenericHashResult()
                        {
                            Success = true,
                            Message = $"File \"{sourceFilePath}\" succesfully hashed.",
                            Hash = sb.ToString()
                        };
                    }
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
    }
}
