/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class SHA384 : HashBase
    {
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA384, bytesToComputeHash);
        }

        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA384, stringToComputeHash);
        }

        public GenericHashResult ComputeFileHash(string sourceFilePath)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.SHA384, sourceFilePath);
        }

        public GenericHashResult VerifyHash(string base64HashString, string stringToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA384, base64HashString, stringToVerifyHash);
        }

        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA384, hashBytes, bytesToVerifyHash);
        }

        public GenericHashResult VerifyFileHash(string base64HashString, string sourceFilePath)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA384, base64HashString, sourceFilePath);
        }

        public GenericHashResult VerifyFileHash(byte[] hashBytes, string sourceFilePath)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA384, hashBytes, sourceFilePath);
        }
    }
}
