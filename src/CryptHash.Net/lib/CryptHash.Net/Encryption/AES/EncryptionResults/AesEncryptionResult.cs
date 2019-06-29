namespace CryptHash.Net.Encryption.AES.EncryptionResults
{
    public class AesEncryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public byte[] EncryptedDataBytes { get; set; }
        public byte[] DecryptedDataBytes { get; set; }
        public string EncryptedDataString { get; set; }
        public string DecryptedDataString { get; set; }
        public byte[] IVOrNonce { get; set; }
        public byte[] Tag { get; set; }
        public byte[] Key { get; set; }
    }
}
