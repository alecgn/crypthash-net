/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using System;
using BCryptNet = BCrypt.Net;

namespace CryptHash.Net.Hash
{
    public class BCrypt
    {
        public GenericHashResult HashString(string stringToBeHashed)
        {
            if (string.IsNullOrWhiteSpace(stringToBeHashed))
            {
                throw new ArgumentException("String to be hashed required.", nameof(stringToBeHashed));
            }

            try
            {
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToBeHashed);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = "String succesfully hashed.",
                    Hash = hashedString
                };
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
        }

        public GenericHashResult Verify(string stringToBeVerified, string hashedString)
        {
            if (string.IsNullOrWhiteSpace(stringToBeVerified))
            {
                throw new ArgumentException("String to be verified required.", nameof(stringToBeVerified));
            }

            try
            {
                var match = BCryptNet.BCrypt.Verify(stringToBeVerified, hashedString);

                if (match)
                {
                    return new GenericHashResult()
                    {
                        Success = true,
                        Message = "String and hash match.",
                        Hash = hashedString
                    };
                }
                else
                {
                    return new GenericHashResult()
                    {
                        Success = false,
                        Message = "String and hash does not match.",
                        Hash = null
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
        }
    }
}
