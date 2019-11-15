/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Hash.HMAC.Base;

namespace CryptHash.Net.Hash.HMAC
{
    public class HMAC_SHA_512 : HMACBase
    {
        public HMACHashResult HashBytes(byte[] bytesToBeHashed, byte[] key = null)
        {
            return base.ComputeHMAC(Enums.HashAlgorithm.SHA512, bytesToBeHashed, key);
        }

        public HMACHashResult HashString(string stringToBeHashed, byte[] key = null)
        {
            return base.ComputeHMAC(Enums.HashAlgorithm.SHA512, stringToBeHashed, key);
        }

        public HMACHashResult HashFile(string sourceFilePath, byte[] key = null)
        {
            return base.ComputeFileHMAC(Enums.HashAlgorithm.SHA512, sourceFilePath, key);
        }
    }
}