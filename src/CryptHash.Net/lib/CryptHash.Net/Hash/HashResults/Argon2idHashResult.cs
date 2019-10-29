/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

namespace CryptHash.Net.Hash.HashResults
{
    public class Argon2idHashResult : GenericHashResult
    {
        public byte[] SaltBytes { get; set; }
        public int Iterations { get; set; }
        public int DegreeOfParallelism { get; set; }
        public int KBMemorySize { get; set; }
        public byte[] AssociatedData { get; set; }
        public byte[] KnownSecret { get; set; }
    }
}
