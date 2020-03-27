/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using CommandLine;

namespace CryptHash.Net.CLI.CommandLineParser
{
    [Verb("crypt", HelpText = "String and file encryption (Authenticated AES 128/192/256 CBC and AES 128/256 GCM).")]
    public class CryptOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"aes128cbc\", \"aes192cbc\", \"aes256cbc\", \"aes128gcm\" and \"aes256gcm\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to be encrypted (string or file path).")]
        public string InputToBeEncrypted { get; set; }

        [Option('p', "password", Required = true, HelpText = "Password for encryption.")]
        public string Password { get; set; }

        [Option('o', "output", HelpText = "Output encrypted file (only for \"file\" input type).")]
        public string OutputFilePath { get; set; }

        [Option('d', "delete-source-file", Default = false, HelpText = "Delete source file after encryption (only for \"file\" input type).")]
        public bool DeleteSourceFile { get; set; }

        [Option("associated-data", Default = null, HelpText = "Associated Data (only for \"AES128GCM\" and \"AES256GCM\"  AEAD encryption algorithm).")]
        public string AssociatedData { get; set; }
    }

    [Verb("decrypt", HelpText = "String and file decryption (Authenticated AES 128/192/256 CBC and AES 128/256 GCM).")]
    public class DecryptOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"aes128cbc\", \"aes192cbc\", \"aes256cbc\", \"aes128gcm\" and \"aes256gcm\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to be decrypted (string or file path).")]
        public string InputToBeDecrypted { get; set; }

        [Option('p', "password", Required = true, HelpText = "Password for decryption.")]
        public string Password { get; set; }

        [Option('o', "output", HelpText = "Output decrypted file (only for \"file\" input type).")]
        public string OutputFilePath { get; set; }

        [Option('d', "delete-encrypted-file", Default = false, HelpText = "Delete encrypted file after decryption (only for \"file\" input type).")]
        public bool DeleteEncryptedFile { get; set; }

        [Option("associated-data", Default = null, HelpText = "Associated Data (only for \"AES128GCM\" and \"AES256GCM\" AEAD encryption algorithm).")]
        public string AssociatedData { get; set; }
    }

    [Verb("hash", HelpText = "String and file hash (MD5, SHA1, SHA256, SHA384, SHA512, PBKDF2 and BCrypt).")]
    public class HashOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"md5\", \"sha1\", \"sha256\", \"sha384\", \"sha512\", \"pbkdf2\" and \"bcrypt\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to compute hash (string or file path).")]
        public string InputToComputeHash { get; set; }

        [Option('c', "compare-hash", Default = null, HelpText = "Previously generated hash for comparation with computed hash.")]
        public string CompareHash { get; set; }
    }

    [Verb("hmac", HelpText = "String and file HMAC (HMAC-MD5, HMAC-SHA1, HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512).")]
    public class HMACOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"hmacmd5\", \"hmacsha1\", \"hmacsha256\", \"hmacsha384\" and \"hmacsha512\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to compute HMAC (string or file path).")]
        public string InputToComputeHMAC { get; set; }

        [Option('k', "key", Default = null, HelpText = "Input key.")]
        public string Key { get; set; }

        [Option('c', "compare-hmac", Default = null, HelpText = "Previously generated HMAC for comparation with computed HMAC.")]
        public string CompareHash { get; set; }
    }

    [Verb("argon2id", HelpText = "Argon2id string hash.")]
    public class Argon2idHashOptions
    {
        [Option('i', "input", Required = true, HelpText = "Input string to compute Argon2id hash.")]
        public string InputToComputeHash { get; set; }

        [Option("iterations", Required = true, HelpText = "Number of iterations.")]
        public int Iterations { get; set; }

        [Option('m', "memory-size", Required = true, HelpText = "Memory size in kilobytes.")]
        public int MemorySize { get; set; }

        [Option('s', "salt", Default = null, HelpText = "Salt.")]
        public string Salt { get; set; }

        [Option('a', "associated-data", Default = null, HelpText = "Associated data.")]
        public string AssociatedData { get; set; }

        [Option('d', "degree-of-parallelism", Default = 0, HelpText = "Degree of parallelism (number of processor's cores to use).")]
        public int DegreeOfParallelism { get; set; }

        [Option('b', "amount-bytes-to-return", Required = true, HelpText = "Amount bytes to return.")]
        public int AmountBytesToReturn { get; set; }

        [Option('c', "compare-hash", Default = null, HelpText = "Previously generated HMAC for comparation with computed HMAC.")]
        public string CompareHash { get; set; }
    }

    [Verb("encode", HelpText = "String encode (Base64 and Hexadecimal).")]
    public class EncodeOptions
    {
        [Option('t', "encode-type", Required = true, HelpText = "Encode type (\"base64\" or \"hex\").")]
        public string EncodeType { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input string to encode.")]
        public string InputToEncode { get; set; }
    }

    [Verb("decode", HelpText = "String decode (Base64 and Hexadecimal).")]
    public class DecodeOptions
    {
        [Option('t', "decode-type", Required = true, HelpText = "Decode type (\"base64\" or \"hex\").")]
        public string DecodeType { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input string to decode.")]
        public string InputToDecode { get; set; }
    }
}
