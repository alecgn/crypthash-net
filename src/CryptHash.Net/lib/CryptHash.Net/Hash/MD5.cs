/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class MD5 : HashBase
    {
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.MD5, bytesToComputeHash);
        }

        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.MD5, stringToComputeHash);
        }

        public GenericHashResult ComputeFileHash(string sourceFilePath)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.MD5, sourceFilePath);
        }
    }
}
