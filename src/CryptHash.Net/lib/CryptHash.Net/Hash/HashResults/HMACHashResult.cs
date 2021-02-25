/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Enums;

namespace CryptHash.Net.Hash.HashResults
{
    public class HMACHashResult : GenericHashResult
    {
        public byte[] Key { get; set; }
        public HMACAlgorithm PRF { get; set; }
    }
}
