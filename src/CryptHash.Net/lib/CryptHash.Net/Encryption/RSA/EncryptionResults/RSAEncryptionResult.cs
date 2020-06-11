using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.RSA.EncryptionResults
{
    public class RSAEncryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public RSAParameters RSAParameters { get; set; }
        public byte[] EncryptedDataBytes { get; set; }
    }
}
