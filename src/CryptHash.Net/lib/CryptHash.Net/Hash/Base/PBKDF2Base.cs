/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

//using CryptHash.Net.Util;
//using CryptHash.Net.Hash.HashResults;
//using Microsoft.AspNetCore.Cryptography.KeyDerivation;
//using System;

//namespace CryptHash.Net.Hash
//{
//    public abstract class PBKDF2Base
//    {
//        private static readonly int _saltBitSize = 128;
//        private static readonly int _saltBytesLength = (_saltBitSize / 8);

//        private static readonly int _iterationsForKeyDerivationFunction = 100000;

//        internal PBKDF2HashResult ComputeHash(Enums.HMACAlgorithm hmacAlgorithm, string stringToComputeHash, byte[] salt = null, 
//            int iterationCount = 0)
//        {
//            if (string.IsNullOrWhiteSpace(stringToComputeHash))
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = false,
//                    Message = MessageDictionary.Instance["Hash.InputRequired"]
//                };
//            }

//            KeyDerivationPrf prf;

//            switch (hmacAlgorithm)
//            {
//                case Enums.HMACAlgorithm.HMACSHA1:
//                    {
//                        prf = KeyDerivationPrf.HMACSHA1;
//                    }
//                    break;
//                case Enums.HMACAlgorithm.HMACSHA256:
//                    {
//                        prf = KeyDerivationPrf.HMACSHA256;
//                    }
//                    break;
//                case Enums.HMACAlgorithm.HMACSHA512:
//                    {
//                        prf = KeyDerivationPrf.HMACSHA512;
//                    }
//                    break;
//                default:
//                    {
//                        return new PBKDF2HashResult()
//                        {
//                            Success = false,
//                            Message = $"{MessageDictionary.Instance["Common.AlgorithmNotSupported"]} \"{hmacAlgorithm.ToString()}\"."
//                        };
//                    }
//            }

//            //salt = salt ?? CommonMethods.GenerateSalt(_saltBytesLength);
//            salt = salt ?? CommonMethods.GenerateSalt();
//            iterationCount = (iterationCount == 0 ? _iterationsForKeyDerivationFunction : iterationCount);
//            byte[] hash;

//            try
//            {
//                hash = KeyDerivation.Pbkdf2(
//                    password: stringToComputeHash,
//                    salt: salt,
//                    prf: prf,
//                    iterationCount: iterationCount,
//                    numBytesRequested: HMACOutputLengthDictionary.Instance[hmacAlgorithm]
//                );

//                var hashBytes = new byte[(_saltBytesLength + HMACOutputLengthDictionary.Instance[hmacAlgorithm])];
//                Array.Copy(salt, 0, hashBytes, 0, _saltBytesLength);
//                Array.Copy(hash, 0, hashBytes, _saltBytesLength, HMACOutputLengthDictionary.Instance[hmacAlgorithm]);

//                return new PBKDF2HashResult()
//                {
//                    Success = true,
//                    Message = MessageDictionary.Instance["Hash.Compute.Success"],
//                    HashString = Convert.ToBase64String(hashBytes),
//                    HashBytes = hashBytes,
//                    Salt = salt,
//                    PRF = hmacAlgorithm,
//                    Iterations = iterationCount
//                };
//            }
//            catch (Exception ex)
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = false,
//                    Message = ex.ToString()
//                };
//            }
//        }

//        internal PBKDF2HashResult VerifyHash(Enums.HMACAlgorithm hmacAlgorithm, string stringToBeVerified, string hash, 
//            int iterationCount = 0)
//        {
//            if (string.IsNullOrWhiteSpace(stringToBeVerified))
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = false,
//                    Message = MessageDictionary.Instance["Hash.InputRequired"]
//                };
//            }

//            if (string.IsNullOrWhiteSpace(hash))
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = false,
//                    Message = MessageDictionary.Instance["Hash.VerificationHashRequired"]
//                };
//            }

//            var hashWithSaltBytes = Convert.FromBase64String(hash);

//            if (hashWithSaltBytes.Length != (_saltBytesLength + HMACOutputLengthDictionary.Instance[hmacAlgorithm]))
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = false,
//                    Message = MessageDictionary.Instance["Common.IncorrectInputLengthError"]
//                };
//            }

//            var saltBytes = new byte[_saltBytesLength];
//            Array.Copy(hashWithSaltBytes, 0, saltBytes, 0, _saltBytesLength);

//            var hashBytes = new byte[HMACOutputLengthDictionary.Instance[hmacAlgorithm]];
//            Array.Copy(hashWithSaltBytes, _saltBytesLength, hashBytes, 0, HMACOutputLengthDictionary.Instance[hmacAlgorithm]);

//            var result = ComputeHash(hmacAlgorithm, stringToBeVerified, saltBytes, iterationCount);

//            if (string.Equals(result.HashString, hash))
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = true,
//                    Message = MessageDictionary.Instance["Hash.Match"],
//                    HashString = hash,
//                    HashBytes = result.HashBytes,
//                    PRF = hmacAlgorithm,
//                    Salt = saltBytes
//                };
//            }
//            else
//            {
//                return new PBKDF2HashResult()
//                {
//                    Success = false,
//                    Message = MessageDictionary.Instance["Hash.DoesNotMatch"]
//                };
//            }
//        }
//    }
//}
