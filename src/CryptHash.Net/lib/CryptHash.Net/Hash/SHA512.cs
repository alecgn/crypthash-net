/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using System;
using System.IO;
using System.Text;

namespace CryptHash.Core.Hash
{
    public static class SHA512
    {
        public static GenericHashResult HashString(string stringToBeHashed)
        {
            if (string.IsNullOrWhiteSpace(stringToBeHashed))
            {
                throw new ArgumentException("String to be hashed required.", nameof(stringToBeHashed));
            }

            StringBuilder sb = null;
            GenericHashResult result = null;

            try
            {
                using (var sha512 = System.Security.Cryptography.SHA512Managed.Create())
                {
                    byte[] stringToBeHashedBytes = Encoding.UTF8.GetBytes(stringToBeHashed);
                    byte[] hashedBytes = sha512.ComputeHash(stringToBeHashedBytes);


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
                    Message = ex.ToString(),
                    Hash = null
                };
            }
            finally
            {
                sb.Clear();
                sb = null;
            }

            return result;
        }

        public static GenericHashResult HashFile(string sourceFilePath)
        {
            if (!File.Exists(sourceFilePath))
            {
                throw new FileNotFoundException($"File \"{sourceFilePath}\" not found.", nameof(sourceFilePath));
            }

            StringBuilder sb = null;
            GenericHashResult result = null;

            try
            {
                using (var sha512 = System.Security.Cryptography.SHA512Managed.Create())
                {
                    using (var fs = File.OpenRead(sourceFilePath))
                    {
                        sb = new StringBuilder();
                        var hashedBytes = sha512.ComputeHash(fs);

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
                    Message = ex.ToString(),
                    Hash = null
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
