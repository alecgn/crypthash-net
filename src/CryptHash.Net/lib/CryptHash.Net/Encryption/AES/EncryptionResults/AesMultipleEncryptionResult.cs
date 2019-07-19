using System;
using System.Collections.Generic;
using System.Text;

namespace CryptHash.Net.Encryption.AES.EncryptionResults
{
    public class AesMultipleEncryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public List<AesEncryptionResult> AesEncryptionResults { get; set; }
    }
}
