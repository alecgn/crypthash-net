using CryptHash.Net.Util;
using CryptHash.Net.Hash.HashResults;
using System;
using System.Security.Cryptography;

namespace CryptHash.Net.Hash
{
    [Obsolete("This class is obsolete. Use PBKDF2.cs class instead.")]
    public class PBKDF2_HMAC_SHA_1
    {
        private static readonly int _hashBitSize = 160;
        private static readonly int _hashBytesLength = (_hashBitSize / 8);

        private static readonly int _saltBitSize = 128;
        private static readonly int _saltBytesLength = (_saltBitSize / 8);

        private static readonly int _iterations = 100000;

        public GenericHashResult HashString(string stringToBeHashed, byte[] salt = null)
        {
            if (string.IsNullOrWhiteSpace(stringToBeHashed))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "String to be hashed required."
                };
            }

            //salt = salt ?? CommonMethods.GenerateRandomBytes(_saltBytesLength);
            salt = salt ?? CommonMethods.GenerateSalt();
            byte[] hash;

            try
            {
                using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(stringToBeHashed, salt))
                {
                    rfc2898DeriveBytes.IterationCount = _iterations;
                    hash = rfc2898DeriveBytes.GetBytes(_hashBytesLength);
                }

                var hashBytes = new byte[(_saltBytesLength + _hashBytesLength)];
                Array.Copy(salt, 0, hashBytes, 0, _saltBytesLength);
                Array.Copy(hash, 0, hashBytes, _saltBytesLength, _hashBytesLength);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = "String succesfully hashed.",
                    HashString = $"{Convert.ToBase64String(hashBytes)}",
                    HashBytes = hashBytes
                };
            }
            catch (Exception ex)
            {
                return new GenericHashResult() { 
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public GenericHashResult VerifyHash(string stringToBeVerified, string hash)
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

            var hashWithSaltBytes = Convert.FromBase64String(hash);

            if (hashWithSaltBytes.Length != (_saltBytesLength + _hashBytesLength))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = "Incorrect data length."
                };
            }

            var saltBytes = new byte[_saltBytesLength];
            Array.Copy(hashWithSaltBytes, 0, saltBytes, 0, _saltBytesLength);

            var hashBytes = new byte[_hashBytesLength];
            Array.Copy(hashWithSaltBytes, _saltBytesLength, hashBytes, 0, _hashBytesLength);

            var result = HashString(stringToBeVerified, saltBytes);

            if (string.Equals(result.HashString, hash))
            {
                return new GenericHashResult()
                {
                    Success = true,
                    Message = "String and hash match.",
                    HashString = hash,
                    HashBytes = result.HashBytes
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
    }
}
