/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using CryptHash.Net.Hash.HashResults;
using BCryptNet = BCrypt.Net;

namespace CryptHash.Net.Hash
{
    public class BCrypt
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
                    Message = ex.ToString()
                };
            }
        }

        public GenericHashResult Verify(string stringToBeVerified, string hashedString)
        {
            if (string.IsNullOrWhiteSpace(stringToBeVerified))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "String to be verified required."
                };
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
                        Message = "String and hash does not match."
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
        }
    }
}
