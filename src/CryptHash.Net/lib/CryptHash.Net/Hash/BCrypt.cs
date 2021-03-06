﻿/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Resources;
using System;
using BCryptNet = BCrypt.Net;

namespace CryptHash.Net.Hash
{
    public class BCrypt
    {
        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            try
            {
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToComputeHash);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
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

        public GenericHashResult ComputeHash(string stringToComputeHash, string salt)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            try
            {
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToComputeHash, salt);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
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

        public GenericHashResult ComputeHash(string stringToComputeHash, string salt, bool enhancedEntropy, BCryptNet.HashType hashType = BCryptNet.HashType.SHA384)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            try
            {
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToComputeHash, salt, enhancedEntropy, hashType);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
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

        public GenericHashResult ComputeHash(string stringToComputeHash, int workFactor, bool enhancedEntropy = false)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            try
            {
                var hashedString = BCryptNet.BCrypt.HashPassword(stringToComputeHash, workFactor, enhancedEntropy);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
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

        public GenericHashResult VerifyHash(string stringToComputeHash, string hash, bool enhancedEntropy = false, BCryptNet.HashType hashType = BCryptNet.HashType.SHA384)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired
                };
            }

            if (string.IsNullOrWhiteSpace(hash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashRequired
                };
            }

            try
            {
                var match = BCryptNet.BCrypt.Verify(stringToComputeHash, hash, enhancedEntropy, hashType);

                if (match)
                {
                    return new GenericHashResult()
                    {
                        Success = true,
                        Message = MessageStrings.Hash_Match,
                        HashString = hash
                    };
                }
                else
                {
                    return new GenericHashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Hash_DoesNotMatch
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
