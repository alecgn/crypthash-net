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
        public GenericHashResult ComputeHash(string stringToBeHashed)
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
                    HashString = hashedString
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

        public GenericHashResult ComputeHash(string stringToBeHashed, string salt)
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
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToBeHashed, salt);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = "String succesfully hashed.",
                    HashString = hashedString
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

        public GenericHashResult ComputeHash(string stringToBeHashed, string salt, bool enhancedEntropy, BCryptNet.HashType hashType = BCryptNet.HashType.SHA384)
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
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToBeHashed, salt, enhancedEntropy, hashType);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = "String succesfully hashed.",
                    HashString = hashedString
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

        public GenericHashResult ComputeHash(string stringToBeHashed, int workFactor, bool enhancedEntropy = false)
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
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToBeHashed, workFactor, enhancedEntropy);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = "String succesfully hashed.",
                    HashString = hashedString
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

        public GenericHashResult VerifyHash(string stringToBeVerified, string hash, bool enhancedEntropy = false, BCryptNet.HashType hashType = BCryptNet.HashType.SHA384)
        {
            if (string.IsNullOrWhiteSpace(stringToBeVerified))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "String to be verified required."
                };
            }

            if (string.IsNullOrWhiteSpace(hash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "Hash required."
                };
            }

            try
            {
                var match = BCryptNet.BCrypt.Verify(stringToBeVerified, hash, enhancedEntropy, hashType);

                if (match)
                {
                    return new GenericHashResult()
                    {
                        Success = true,
                        Message = "String and hash match.",
                        HashString = hash
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
