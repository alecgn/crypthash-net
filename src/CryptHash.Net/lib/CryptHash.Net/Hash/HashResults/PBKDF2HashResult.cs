/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Enums;

namespace CryptHash.Net.Hash.HashResults
{
    public class PBKDF2HashResult : GenericHashResult
    {
        public byte[] Salt { get; set; }
        public HMACAlgorithm PRF { get; set; }
        public int Iterations { get; set; }
    }
}
