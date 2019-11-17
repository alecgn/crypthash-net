/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Hash.Base;

namespace CryptHash.Net.Hash
{
    public class HMAC_SHA_1 : HMACBase
    {
        public HMACHashResult HashBytes(byte[] bytesToBeHashed, byte[] key = null)
        {
            return base.ComputeHMAC(Enums.HashAlgorithm.SHA1, bytesToBeHashed, key);
        }

        public HMACHashResult HashString(string stringToBeHashed, byte[] key = null)
        {
            return base.ComputeHMAC(Enums.HashAlgorithm.SHA1, stringToBeHashed, key);
        }

        public HMACHashResult HashFile(string sourceFilePath, byte[] key = null)
        {
            return base.ComputeFileHMAC(Enums.HashAlgorithm.SHA1, sourceFilePath, key);
        }
    }
}