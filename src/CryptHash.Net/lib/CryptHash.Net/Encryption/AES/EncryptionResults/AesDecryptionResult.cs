/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.Enums;
using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.AES.EncryptionResults
{
    public class AesDecryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        //public byte[] EncryptedDataBytes { get; set; }
        //public string EncryptedDataBase64String { get; set; }
        public byte[] DecryptedDataBytes { get; set; }
        public string DecryptedDataString { get; set; }
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
        public byte[] Nonce { get; set; }
        //public CipherMode CipherMode { get; set; }
        public AesCipherMode AesCipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
        //public byte[] CryptSalt { get; set; }
        //public byte[] AuthSalt { get; set; }
        public byte[] Salt { get; set; }
        public byte[] Tag { get; set; }
    }
}
