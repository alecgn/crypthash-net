//using CryptHash.Net.Encryption.Utils;
//using CryptHash.Net.Hash.HashResults;
//using System;
//using System.Collections.Generic;
//using System.Security.Cryptography;
//using System.Text;

//namespace CryptHash.Net.Hash
//{
//    public class PBKDF2_HMAC_SHA_1
//    {
//        private static readonly int _hashBitSize = 160;
//        private static readonly int _hashBytesLength = (_hashBitSize / 8);

//        private static readonly int _saltBitSize = 256;
//        private static readonly int _saltBytesLength = (_hashBitSize / 8);

//        private static readonly int _iterations = 100000;

//        public GenericHashResult HashString(string stringToBeHashed)
//        {
//            byte[] hash;
//            byte[] salt;

//            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(stringToBeHashed, _saltBytesLength))
//            {
//                rfc2898DeriveBytes.IterationCount = _iterations;
//                hash = rfc2898DeriveBytes.GetBytes(_hashBytesLength);
//                salt = rfc2898DeriveBytes.Salt;
//            }

//            return new GenericHashResult()
//            {
//                Success = true,
//                Message = "String succesfully hashed.",
//                Hash = $"{Convert.ToBase64String(salt)}|{Convert.ToBase64String(hash)}"
//            };
//        }

//        public GenericHashResult Verify(string stringToBeVerified, string hashedString)
//        {
//            var result = HashString(stringToBeVerified);

//            if (string.Equals(result.Hash, hashedString))
//            {
//                return new GenericHashResult()
//                {
//                    Success = true,
//                    Message = "String and hash match.",
//                    Hash = hashedString
//                };
//            }
//            else
//            {
//                return new GenericHashResult()
//                {
//                    Success = false,
//                    Message = "String and hash does not match."
//                };
//            }
//        }
//    }
//}
