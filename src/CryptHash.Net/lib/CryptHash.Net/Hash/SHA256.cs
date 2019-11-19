/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class SHA256 : HashBase
    {
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA256, bytesToComputeHash);
        }

        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA256, stringToComputeHash);
        }

        public GenericHashResult ComputeFileHash(string sourceFilePath)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.SHA256, sourceFilePath);
        }
    }
}
