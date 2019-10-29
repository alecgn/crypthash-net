/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

namespace CryptHash.Net.Hash.HashResults
{
    public class GenericHashResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string HashString { get; set; }
        public byte[] HashBytes { get; set; }
    }
}
