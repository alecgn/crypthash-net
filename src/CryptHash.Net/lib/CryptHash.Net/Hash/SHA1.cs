﻿/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class SHA1 : HashBase
    {
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA1, bytesToComputeHash);
        }

        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA1, stringToComputeHash);
        }

        public GenericHashResult ComputeFileHash(string filePathToComputeHash)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.SHA1, filePathToComputeHash);
        }

        public GenericHashResult VerifyHash(string base64HashString, string stringToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA1, base64HashString, stringToVerifyHash);
        }

        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA1, hashBytes, bytesToVerifyHash);
        }

        public GenericHashResult VerifyFileHash(string base64HashString, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA1, base64HashString, filePathToVerifyHash);
        }

        public GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA1, hashBytes, filePathToVerifyHash);
        }
    }
}
