/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

namespace CryptHash.Net.Hash.HashResults
{
    public class PBKDF2HashResult : GenericHashResult
    {
        public byte[] Salt { get; set; }
        public byte[] PRF { get; set; }
    }
}
