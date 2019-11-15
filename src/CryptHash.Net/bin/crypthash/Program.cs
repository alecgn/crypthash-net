/*
 *      Alessandro Cagliostro, 2019
 *
 *      https://github.com/alecgn
 */

using System;
using System.Collections.Generic;
using System.Text;
using CommandLine;
using CommandLine.Text;
using CryptHash.Net.CLI.CommandLineParser;
using CryptHash.Net.CLI.ConsoleUtil;
using CryptHash.Net.Encryption.AES.AE;
using CryptHash.Net.Encryption.AES.AEAD;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Hash;
using CryptHash.Net.Hash.Hash;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.CLI
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                ProcessArgs(args);
            }
            catch (Exception ex)
            {
                ShowErrorMessage(ex.Message);

                Environment.Exit((int)ExitCode.Error);
            }
        }

        private static void ProcessArgs(string[] args)
        {

            var parserResult = Parser.Default.ParseArguments<CryptOptions, DecryptOptions, HashOptions>(args);

            var exitCode = parserResult.MapResult(
                (CryptOptions opts) => RunCryptOptionsAndReturnExitCode(opts),
                (DecryptOptions opts) => RunDecryptOptionsAndReturnExitCode(opts),
                (HashOptions opts) => RunHashOptionsAndReturnExitCode(opts),
                errors => HandleParseError(errors, parserResult)
            );

            Environment.Exit((int)exitCode);
        }

        private static ExitCode RunCryptOptionsAndReturnExitCode(CryptOptions cryptOptions)
        {
            AesEncryptionResult aesEncryptionResult = null;

            switch (cryptOptions.InputType.ToLower())
            {
                case "string":
                    {
                        switch (cryptOptions.Algorithm.ToLower())
                        {
                            case "aes128cbc":
                                    aesEncryptionResult = new AE_AES_128_CBC_HMAC_SHA_256().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password);
                                break;
                            case "aes192cbc":
                                    aesEncryptionResult = new AE_AES_192_CBC_HMAC_SHA_384().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password);
                                break;
                            case "aes256cbc":
                                    aesEncryptionResult = new AE_AES_256_CBC_HMAC_SHA_512().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password);
                                break;
                            case "aes256gcm":
                                    aesEncryptionResult = new AEAD_AES_256_GCM().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password, cryptOptions.AssociatedData);
                                break;
                            default:
                                aesEncryptionResult = new AesEncryptionResult() { Success = false, Message = $"Unknown algorithm \"{cryptOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                case "file":
                    {
                        switch (cryptOptions.Algorithm.ToLower())
                        {
                            case "aes128cbc":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var aes128 = new AE_AES_128_CBC_HMAC_SHA_256();
                                        aes128.OnEncryptionProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        aes128.OnEncryptionMessage += (msg) => { /*Console.WriteLine(msg);*/ progressBar.WriteLine(msg); };

                                        aesEncryptionResult = aes128.EncryptFile(cryptOptions.InputToBeEncrypted, cryptOptions.OutputFilePath, cryptOptions.Password, cryptOptions.DeleteSourceFile);
                                    }
                                }
                                break;
                            case "aes192cbc":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var aes192 = new AE_AES_192_CBC_HMAC_SHA_384();
                                        aes192.OnEncryptionProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        aes192.OnEncryptionMessage += (msg) => { /*Console.WriteLine(msg);*/ progressBar.WriteLine(msg); };

                                        aesEncryptionResult = aes192.EncryptFile(cryptOptions.InputToBeEncrypted, cryptOptions.OutputFilePath, cryptOptions.Password, cryptOptions.DeleteSourceFile);
                                    }
                                }
                                break;
                            case "aes256cbc":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var aes256 = new AE_AES_256_CBC_HMAC_SHA_512();
                                        aes256.OnEncryptionProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        aes256.OnEncryptionMessage += (msg) => { /*Console.WriteLine(msg);*/ progressBar.WriteLine(msg); };

                                        aesEncryptionResult = aes256.EncryptFile(cryptOptions.InputToBeEncrypted, cryptOptions.OutputFilePath, cryptOptions.Password, cryptOptions.DeleteSourceFile);
                                    }
                                }
                                break;
                            case "aes256gcm":
                                aesEncryptionResult = new AesEncryptionResult() { Success = false, Message = $"Algorithm \"{cryptOptions.Algorithm}\" currently not available for file encryption." };
                                break;
                            default:
                                aesEncryptionResult = new AesEncryptionResult() { Success = false, Message = $"Unknown algorithm \"{cryptOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                default:
                    aesEncryptionResult = new AesEncryptionResult() { Success = false, Message = $"Unknown input type \"{cryptOptions.InputType}\"." };
                    break;
            }

            if (aesEncryptionResult.Success)
            {
                Console.WriteLine((cryptOptions.InputType.ToLower().Equals("string") ? aesEncryptionResult.EncryptedDataBase64String : aesEncryptionResult.Message));

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(aesEncryptionResult.Message);

                return ExitCode.Error;
            }
        }

        private static ExitCode RunDecryptOptionsAndReturnExitCode(DecryptOptions decryptOptions)
        {
            AesDecryptionResult aesDecryptionResult = null;

            switch (decryptOptions.InputType.ToLower())
            {
                case "string":
                    {
                        switch (decryptOptions.Algorithm.ToLower())
                        {
                            case "aes128cbc":
                                aesDecryptionResult = new AE_AES_128_CBC_HMAC_SHA_256().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password);
                                break;
                            case "aes192cbc":
                                aesDecryptionResult = new AE_AES_192_CBC_HMAC_SHA_384().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password);
                                break;
                            case "aes256cbc":
                                aesDecryptionResult = new AE_AES_256_CBC_HMAC_SHA_512().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password);
                                break;
                            case "aes256gcm":
                                aesDecryptionResult = new AEAD_AES_256_GCM().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password, decryptOptions.AssociatedData);
                                break;
                            default:
                                aesDecryptionResult = new AesDecryptionResult() { Success = false, Message = $"Unknown algorithm \"{decryptOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                case "file":
                    {
                        switch (decryptOptions.Algorithm.ToLower())
                        {
                            case "aes128cbc":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var aes128 = new AE_AES_128_CBC_HMAC_SHA_256();
                                        aes128.OnDecryptionProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        aes128.OnDecryptionMessage += (msg) => { /*Console.WriteLine(msg);*/ progressBar.WriteLine(msg); };

                                        aesDecryptionResult = aes128.DecryptFile(decryptOptions.InputToBeDecrypted, decryptOptions.OutputFilePath, decryptOptions.Password, decryptOptions.DeleteEncryptedFile);
                                    }
                                }
                                break;
                            case "aes192cbc":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var aes192 = new AE_AES_192_CBC_HMAC_SHA_384();
                                        aes192.OnDecryptionProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        aes192.OnDecryptionMessage += (msg) => { /*Console.WriteLine(msg);*/ progressBar.WriteLine(msg); };

                                        aesDecryptionResult = aes192.DecryptFile(decryptOptions.InputToBeDecrypted, decryptOptions.OutputFilePath, decryptOptions.Password, decryptOptions.DeleteEncryptedFile);
                                    }
                                }
                                break;
                            case "aes256cbc":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var aes256 = new AE_AES_256_CBC_HMAC_SHA_512();
                                        aes256.OnDecryptionProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        aes256.OnDecryptionMessage += (msg) => { /*Console.WriteLine(msg);*/ progressBar.WriteLine(msg); };

                                        aesDecryptionResult = aes256.DecryptFile(decryptOptions.InputToBeDecrypted, decryptOptions.OutputFilePath, decryptOptions.Password, decryptOptions.DeleteEncryptedFile);
                                    }
                                }
                                break;
                            case "aes256gcm":
                                aesDecryptionResult = new AesDecryptionResult() { Success = false, Message = $"Algorithm \"{decryptOptions.Algorithm}\" currently not available for file decryption." };
                                break;
                            default:
                                aesDecryptionResult = new AesDecryptionResult() { Success = false, Message = $"Unknown algorithm \"{decryptOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                default:
                    aesDecryptionResult = new AesDecryptionResult() { Success = false, Message = $"Unknown input type \"{decryptOptions.InputType}\"." };
                    break;
            }

            if (aesDecryptionResult.Success)
            {
                Console.WriteLine((decryptOptions.InputType.ToLower().Equals("string") ? aesDecryptionResult.DecryptedDataString : aesDecryptionResult.Message));

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(aesDecryptionResult.Message);

                return ExitCode.Error;
            }
        }

        private static ExitCode RunHashOptionsAndReturnExitCode(HashOptions hashOptions)
        {
            GenericHashResult hashResult = null;

            switch (hashOptions.InputType.ToLower())
            {
                case "string":
                    {
                        switch (hashOptions.Algorithm.ToLower())
                        {
                            case "md5":
                                hashResult = new MD5().ComputeHash(hashOptions.InputToBeHashed);
                                break;
                            case "sha1":
                                hashResult = new SHA1().ComputeHash(hashOptions.InputToBeHashed);
                                break;
                            case "sha256":
                                hashResult = new SHA256().ComputeHash(hashOptions.InputToBeHashed);
                                break;
                            case "sha384":
                                hashResult = new SHA384().ComputeHash(hashOptions.InputToBeHashed);
                                break;
                            case "sha512":
                                hashResult = new SHA512().ComputeHash(hashOptions.InputToBeHashed);
                                break;
                            case "pbkdf2":
                                hashResult = new PBKDF2().HashString(hashOptions.InputToBeHashed);
                                break;
                            case "bcrypt":
                                hashResult = new Hash.BCrypt().HashString(hashOptions.InputToBeHashed);
                                break;
                            default:
                                hashResult = new GenericHashResult() { Success = false, Message = $"Unknown algorithm \"{hashOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                case "file":
                    {
                        switch (hashOptions.Algorithm.ToLower())
                        {
                            case "md5":
                                //hashResult = new MD5().HashFile(hashOptions.InputToBeHashed);

                                using (var progressBar = new ProgressBar())
                                {
                                    var md5 = new MD5();
                                    md5.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };

                                    hashResult = md5.ComputeFileHash(hashOptions.InputToBeHashed);
                                }
                                break;
                            case "sha1":
                                //hashResult = new SHA1().HashFile(hashOptions.InputToBeHashed);

                                using (var progressBar = new ProgressBar())
                                {
                                    var sha1 = new SHA1();
                                    sha1.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };

                                    hashResult = sha1.ComputeFileHash(hashOptions.InputToBeHashed);
                                }
                                break;
                            case "sha256":
                                //hashResult = new SHA256().HashFile(hashOptions.InputToBeHashed);

                                using (var progressBar = new ProgressBar())
                                {
                                    var sha256 = new SHA256();
                                    sha256.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };

                                    hashResult = sha256.ComputeFileHash(hashOptions.InputToBeHashed);
                                }
                                break;
                            case "sha384":
                                //hashResult = new SHA384().HashFile(hashOptions.InputToBeHashed);

                                using (var progressBar = new ProgressBar())
                                {
                                    var sha384 = new SHA384();
                                    sha384.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };

                                    hashResult = sha384.ComputeFileHash(hashOptions.InputToBeHashed);
                                }
                                break;
                            case "sha512":
                                //hashResult = new SHA512().HashFile(hashOptions.InputToBeHashed);

                                using (var progressBar = new ProgressBar())
                                {
                                    var sha512 = new SHA512();
                                    sha512.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };

                                    hashResult = sha512.ComputeFileHash(hashOptions.InputToBeHashed);
                                }
                                break;
                            case "pbkdf2":
                            case "bcrypt":
                                hashResult = new GenericHashResult() { Success = false, Message = $"Algorithm \"{hashOptions.Algorithm}\" currently not available for file hashing." };
                                break;
                            default:
                                hashResult = new GenericHashResult() { Success = false, Message = $"Unknown algorithm \"{hashOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                default:
                    hashResult = new GenericHashResult() { Success = false, Message = $"Unknown input type \"{hashOptions.InputType}\"." };
                    break;
            }

            if (hashResult.Success && !string.IsNullOrWhiteSpace(hashOptions.CompareHash))
            {
                bool hashesMatch = (
                    hashOptions.Algorithm.ToLower() != "bcrypt" && hashOptions.Algorithm.ToLower() != "pbkdf2"
                        ? (hashResult.HashString).Equals(hashOptions.CompareHash, StringComparison.InvariantCultureIgnoreCase)
                        : (hashOptions.Algorithm.ToLower() == "bcrypt"
                            ? new Hash.BCrypt().VerifyHash(hashOptions.InputToBeHashed, hashOptions.CompareHash).Success
                            : new Hash.PBKDF2().VerifyHash(hashOptions.InputToBeHashed, hashOptions.CompareHash).Success
                        )
                );

                var outputMessage = (
                    hashesMatch
                        ? $"Computed hash MATCH with given hash: {(hashOptions.Algorithm.ToLower() != "bcrypt" ? hashResult.HashString : hashOptions.CompareHash)}"
                        : $"Computed hash DOES NOT MATCH with given hash." +
                        (
                            hashOptions.Algorithm.ToLower() != "bcrypt"
                                ? $"\nComputed hash: {hashResult.HashString}\nGiven hash: {hashOptions.CompareHash}"
                                : ""
                        )
                );

                Console.WriteLine(outputMessage);

                return (hashesMatch ? ExitCode.Sucess : ExitCode.Error);
            }
            else if (hashResult.Success && string.IsNullOrWhiteSpace(hashOptions.CompareHash))
            {
                Console.WriteLine(hashResult.HashString);

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(hashResult.Message);

                return ExitCode.Error;
            }
        }

        private static ExitCode HandleParseError(IEnumerable<Error> errors, ParserResult<object> parserResult)
        {
            HelpText.AutoBuild(parserResult, h =>
            {
                return HelpText.DefaultParsingErrorsHandler(parserResult, h);
            },
            e => { return e; });

            return ExitCode.Error;
        }

        private static void ShowErrorMessage(string errorMessage)
        {
            Console.WriteLine($"An error has occured during processing:\n{errorMessage}");
        }
    }
}
