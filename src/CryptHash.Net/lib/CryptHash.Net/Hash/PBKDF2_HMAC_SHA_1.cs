using CryptHash.Net.Util;
using CryptHash.Net.Hash.HashResults;
using System;
using System.Security.Cryptography;

namespace CryptHash.Net.Hash
{
    //[Obsolete("This class is obsolete. Use PBKDF2.cs class instead.")]
    public class PBKDF2_HMAC_SHA_1
    {
        private static readonly int _hashBitSize = 160;
        private static readonly int _hashBytesLength = (_hashBitSize / 8);

        private static readonly int _saltBitSize = 128;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

        private static readonly int _iterations = 100000;

        public PBKDF2HashResult ComputeHash(string stringToComputeHash, byte[] salt = null)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new PBKDF2HashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Hash.InputRequired"]
                };
            }

            //salt = salt ?? CommonMethods.GenerateRandomBytes(_saltBytesLength);
            salt = salt ?? CommonMethods.GenerateSalt();
            byte[] hash;

            try
            {
                using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(stringToComputeHash, salt))
                {
                    rfc2898DeriveBytes.IterationCount = _iterations;
                    hash = rfc2898DeriveBytes.GetBytes(_hashBytesLength);
                }

                var hashBytes = new byte[(_saltBytesLength + _hashBytesLength)];
                Array.Copy(salt, 0, hashBytes, 0, _saltBytesLength);
                Array.Copy(hash, 0, hashBytes, _saltBytesLength, _hashBytesLength);

                return new PBKDF2HashResult()
                {
                    Success = true,
                    Message = MessageDictionary.Instance["Hash.ComputeSuccess"],
                    HashString = $"{Convert.ToBase64String(hashBytes)}",
                    HashBytes = hashBytes,
                    Iterations = _iterations,
                    Salt = salt,
                    PRF = Enums.HMACAlgorithm.HMACSHA1
                };
            }
            catch (Exception ex)
            {
                return new PBKDF2HashResult() { 
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public PBKDF2HashResult VerifyHash(string stringToBeVerified, string hash)
        {
            if (string.IsNullOrWhiteSpace(stringToBeVerified))
            {
                return new PBKDF2HashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Hash.InputRequired"]
                };
            }

            if (string.IsNullOrWhiteSpace(hash))
            {
                return new PBKDF2HashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Hash.InputRequired"]
                };
            }

            var hashWithSaltBytes = Convert.FromBase64String(hash);

            if (hashWithSaltBytes.Length != (_saltBytesLength + _hashBytesLength))
            {
                return new PBKDF2HashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Common.IncorrectInputLengthError"]
                };
            }

            var saltBytes = new byte[_saltBytesLength];
            Array.Copy(hashWithSaltBytes, 0, saltBytes, 0, _saltBytesLength);

            var hashBytes = new byte[_hashBytesLength];
            Array.Copy(hashWithSaltBytes, _saltBytesLength, hashBytes, 0, _hashBytesLength);

            var result = ComputeHash(stringToBeVerified, saltBytes);

            if (string.Equals(result.HashString, hash))
            {
                return new PBKDF2HashResult()
                {
                    Success = true,
                    Message = MessageDictionary.Instance["Hash.Match"],
                    HashString = hash,
                    HashBytes = result.HashBytes,
                    Iterations = _iterations,
                    Salt = result.Salt,
                    PRF = result.PRF
                };
            }
            else
            {
                return new PBKDF2HashResult()
                {
                    Success = false,
                    Message = MessageDictionary.Instance["Hash.DoesNotMatch"]
                };
            }
        }
    }
}
