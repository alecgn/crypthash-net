/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CommandLine;

namespace CryptHash.Net.CLI.CommandLineParser
{
    [Verb("crypt", HelpText = "String and file encryption (Authenticated AES 128/192/256 CBC).")]
    public class CryptOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"aes128\", \"aes192\" and \"aes256\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to be encrypted (string or file path).")]
        public string InputToBeEncrypted { get; set; }

        [Option('p', "password", Required = true, HelpText = "Password for encryption.")]
        public string Password { get; set; }

        [Option('o', "output", HelpText = "Output encrypted file (only for \"file\" input type).")]
        public string OutputFilePath { get; set; }

        [Option('d', "delete-source-file", Default = false, HelpText = "Delete source file after encryption (only for \"file\" input type).")]
        public bool DeleteSourceFile { get; set; }
    }

    [Verb("decrypt", HelpText = "String and file decryption (Authenticated AES 128/192/256 CBC).")]
    public class DecryptOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"aes128\", \"aes192\" and \"aes256\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to be decrypted (string or file path).")]
        public string InputToBeDecrypted { get; set; }

        [Option('p', "password", Required = true, HelpText = "Password for decryption.")]
        public string Password { get; set; }

        [Option('o', "output", HelpText = "Output decrypted file (only for \"file\" input type).")]
        public string OutputFilePath { get; set; }

        [Option('d', "delete-encrypted-file", Default = false, HelpText = "Delete encrypted file after decryption (only for \"file\" input type).")]
        public bool DeleteEncryptedFile { get; set; }
    }

    [Verb("hash", HelpText = "String and file hashing (MD5, SHA1, SHA256, SHA384, SHA512 and BCrypt).")]
    public class HashOptions
    {
        [Option('t', "input-type", Required = true, HelpText = "Input type (\"string\" or \"file\").")]
        public string InputType { get; set; }

        [Option('a', "algorithm", Required = true, HelpText = "Algorithm (\"md5\", \"sha1\", \"sha256\", \"sha384\", \"sha512\" and \"bcrypt\").")]
        public string Algorithm { get; set; }

        [Option('i', "input", Required = true, HelpText = "Input to be hashed (string or file path).")]
        public string InputToBeHashed { get; set; }

        [Option('c', "compare-hash", Default = null, HelpText = "Previously generated hash for comparation with computed hash.")]
        public string CompareHash { get; set; }
    }
}
