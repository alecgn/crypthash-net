/*
 *      Alessandro Cagliostro, 2021
 *
 *      https://github.com/alecgn
 */

using CommandLine;
using CommandLine.Text;
using CryptHash.Net.CLI.CommandLineParser;
using CryptHash.Net.CLI.ConsoleUtil;
using CryptHash.Net.Encoding;
using CryptHash.Net.Encryption.AES.AE;
using CryptHash.Net.Encryption.AES.AEAD;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Hash;
using CryptHash.Net.Hash.Hash;
using CryptHash.Net.Hash.HashResults;
using System;
using System.Collections.Generic;

namespace CryptHash.Net.CLI
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                ParseArgs(args);
            }
            catch (Exception ex)
            {
                ShowErrorMessage(ex.Message);
                Environment.Exit((int)ExitCode.Error);
            }
        }

        private static void ParseArgs(string[] args)
        {
            var parserResult = Parser.Default.ParseArguments<
                CryptOptions,
                DecryptOptions,
                HashOptions,
                HMACOptions,
                Argon2idHashOptions,
                EncodeOptions,
                DecodeOptions>(args);
            var exitCode = parserResult.MapResult(
                (CryptOptions opts) => RunCryptOptionsAndReturnExitCode(opts),
                (DecryptOptions opts) => RunDecryptOptionsAndReturnExitCode(opts),
                (HashOptions opts) => RunHashOptionsAndReturnExitCode(opts),
                (HMACOptions opts) => RunHMACOptionsAndReturnExitCode(opts),
                (Argon2idHashOptions opts) => RunArgon2idHashOptionsAndReturnExitCode(opts),
                (EncodeOptions opts) => RunEncodeOptionsAndReturnExitCode(opts),
                (DecodeOptions opts) => RunDecodeOptionsAndReturnExitCode(opts),
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
                        aesEncryptionResult = (cryptOptions.Algorithm.ToLower()) switch
                        {
                            "aes128cbc" => new AE_AES_128_CBC_HMAC_SHA_256().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password),
                            "aes192cbc" => new AE_AES_192_CBC_HMAC_SHA_384().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password),
                            "aes256cbc" => new AE_AES_256_CBC_HMAC_SHA_512().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password),
                            "aes128gcm" => new AEAD_AES_128_GCM().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password, cryptOptions.AssociatedData),
                            "aes192gcm" => new AEAD_AES_192_GCM().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password, cryptOptions.AssociatedData),
                            "aes256gcm" => new AEAD_AES_256_GCM().EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password, cryptOptions.AssociatedData),
                            _ => new AesEncryptionResult() { Success = false, Message = $"Unknown algorithm \"{cryptOptions.Algorithm}\"." },
                        };
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
                                        aes128.OnEncryptionMessage += (msg) => { progressBar.WriteLine(msg); };
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
                                        aes192.OnEncryptionMessage += (msg) => { progressBar.WriteLine(msg); };
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
                                        aes256.OnEncryptionMessage += (msg) => { progressBar.WriteLine(msg); };
                                        aesEncryptionResult = aes256.EncryptFile(cryptOptions.InputToBeEncrypted, cryptOptions.OutputFilePath, cryptOptions.Password, cryptOptions.DeleteSourceFile);
                                    }
                                }
                                break;
                            case "aes128gcm":
                            case "aes192gcm":
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
                Console.WriteLine(cryptOptions.InputType.ToLower().Equals("string")
                    ? aesEncryptionResult.EncryptedDataBase64String
                    : aesEncryptionResult.Message);

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
                        aesDecryptionResult = (decryptOptions.Algorithm.ToLower()) switch
                        {
                            "aes128cbc" => new AE_AES_128_CBC_HMAC_SHA_256().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password),
                            "aes192cbc" => new AE_AES_192_CBC_HMAC_SHA_384().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password),
                            "aes256cbc" => new AE_AES_256_CBC_HMAC_SHA_512().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password),
                            "aes128gcm" => new AEAD_AES_128_GCM().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password, decryptOptions.AssociatedData),
                            "aes192gcm" => new AEAD_AES_192_GCM().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password, decryptOptions.AssociatedData),
                            "aes256gcm" => new AEAD_AES_256_GCM().DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password, decryptOptions.AssociatedData),
                            _ => new AesDecryptionResult() { Success = false, Message = $"Unknown algorithm \"{decryptOptions.Algorithm}\"." },
                        };
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
                                        aes128.OnDecryptionMessage += (msg) => { progressBar.WriteLine(msg); };
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
                                        aes192.OnDecryptionMessage += (msg) => { progressBar.WriteLine(msg); };
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
                                        aes256.OnDecryptionMessage += (msg) => { progressBar.WriteLine(msg); };
                                        aesDecryptionResult = aes256.DecryptFile(decryptOptions.InputToBeDecrypted, decryptOptions.OutputFilePath, decryptOptions.Password, decryptOptions.DeleteEncryptedFile);
                                    }
                                }
                                break;
                            case "aes128gcm":
                            case "aes192gcm":
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
                        hashResult = (hashOptions.Algorithm.ToLower()) switch
                        {
                            "md5" => new MD5().ComputeHash(hashOptions.InputToComputeHash),
                            "sha1" => new SHA1().ComputeHash(hashOptions.InputToComputeHash),
                            "sha256" => new SHA256().ComputeHash(hashOptions.InputToComputeHash),
                            "sha384" => new SHA384().ComputeHash(hashOptions.InputToComputeHash),
                            "sha512" => new SHA512().ComputeHash(hashOptions.InputToComputeHash),
                            "pbkdf2" => new PBKDF2_HMAC_SHA_1().ComputeHash(hashOptions.InputToComputeHash),
                            "bcrypt" => new Hash.BCrypt().ComputeHash(hashOptions.InputToComputeHash),
                            _ => new GenericHashResult() { Success = false, Message = $"Unknown algorithm \"{hashOptions.Algorithm}\"." },
                        };
                    }
                    break;
                case "file":
                    {
                        switch (hashOptions.Algorithm.ToLower())
                        {
                            case "md5":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var md5 = new MD5();
                                        md5.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        hashResult = md5.ComputeFileHash(hashOptions.InputToComputeHash);
                                    }
                                }
                                break;
                            case "sha1":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var sha1 = new SHA1();
                                        sha1.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        hashResult = sha1.ComputeFileHash(hashOptions.InputToComputeHash);
                                    }
                                }
                                break;
                            case "sha256":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var sha256 = new SHA256();
                                        sha256.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        hashResult = sha256.ComputeFileHash(hashOptions.InputToComputeHash);
                                    }
                                }
                                break;
                            case "sha384":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var sha384 = new SHA384();
                                        sha384.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        hashResult = sha384.ComputeFileHash(hashOptions.InputToComputeHash);
                                    }
                                }
                                break;
                            case "sha512":
                                {
                                    using (var progressBar = new ProgressBar())
                                    {
                                        var sha512 = new SHA512();
                                        sha512.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                        hashResult = sha512.ComputeFileHash(hashOptions.InputToComputeHash);
                                    }
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
                var hashesMatch = (
                    hashOptions.Algorithm.ToLower() != "bcrypt" && hashOptions.Algorithm.ToLower() != "pbkdf2"
                        ? (hashResult.HashString).Equals(hashOptions.CompareHash, StringComparison.InvariantCultureIgnoreCase)
                        : (hashOptions.Algorithm.ToLower() == "bcrypt"
                            ? new Hash.BCrypt().VerifyHash(hashOptions.InputToComputeHash, hashOptions.CompareHash).Success
                            : new Hash.PBKDF2_HMAC_SHA_1().VerifyHash(hashOptions.InputToComputeHash, hashOptions.CompareHash).Success
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

        private static ExitCode RunHMACOptionsAndReturnExitCode(HMACOptions hmacOptions)
        {
            HMACHashResult hmacResult = null;

            switch (hmacOptions.InputType.ToLower())
            {
                case "string":
                    {
                        hmacResult = (hmacOptions.Algorithm.ToLower()) switch
                        {
                            "hmacmd5" => new HMAC_MD5().ComputeHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key))),
                            "hmacsha1" => new HMAC_SHA_1().ComputeHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key))),
                            "hmacsha256" => new HMAC_SHA_256().ComputeHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key))),
                            "hmacsha384" => new HMAC_SHA_384().ComputeHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key))),
                            "hmacsha512" => new HMAC_SHA_512().ComputeHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key))),
                            _ => new HMACHashResult() { Success = false, Message = $"Unknown algorithm \"{hmacOptions.Algorithm}\"." },
                        };
                    }
                    break;
                case "file":
                    {
                        switch (hmacOptions.Algorithm.ToLower())
                        {
                            case "hmacmd5":
                                using (var progressBar = new ProgressBar())
                                {
                                    var hmacMd5 = new HMAC_MD5();
                                    hmacMd5.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                    hmacResult = hmacMd5.ComputeFileHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key)));
                                }
                                break;
                            case "hmacsha1":
                                using (var progressBar = new ProgressBar())
                                {
                                    var hmacSha1 = new HMAC_SHA_1();
                                    hmacSha1.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                    hmacResult = hmacSha1.ComputeFileHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key)));
                                }
                                break;
                            case "hmacsha256":
                                using (var progressBar = new ProgressBar())
                                {
                                    var hmacSha256 = new HMAC_SHA_256();
                                    hmacSha256.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                    hmacResult = hmacSha256.ComputeFileHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key)));
                                }
                                break;
                            case "hmacsha384":
                                using (var progressBar = new ProgressBar())
                                {
                                    var hmacSha384 = new HMAC_SHA_384();
                                    hmacSha384.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                    hmacResult = hmacSha384.ComputeFileHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key)));
                                }
                                break;
                            case "hmacsha512":
                                using (var progressBar = new ProgressBar())
                                {
                                    var hmacSha512 = new HMAC_SHA_512();
                                    hmacSha512.OnHashProgress += (percentageDone, message) => { progressBar.Report((double)percentageDone / 100); };
                                    hmacResult = hmacSha512.ComputeFileHMAC(hmacOptions.InputToComputeHMAC, (string.IsNullOrWhiteSpace(hmacOptions.Key) ? null : System.Text.Encoding.UTF8.GetBytes(hmacOptions.Key)));
                                }
                                break;
                            default:
                                hmacResult = new HMACHashResult() { Success = false, Message = $"Unknown algorithm \"{hmacOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                default:
                    hmacResult = new HMACHashResult() { Success = false, Message = $"Unknown input type \"{hmacOptions.InputType}\"." };
                    break;
            }

            if (hmacResult.Success && !string.IsNullOrWhiteSpace(hmacOptions.CompareHash))
            {
                if (string.IsNullOrWhiteSpace(hmacOptions.Key))
                {
                    Console.WriteLine("The HMAC KEY parameter is required for comparation.");

                    return ExitCode.Error;
                }
                else
                {
                    var hashesMatch = (hmacResult.HashString.Equals(hmacOptions.CompareHash, StringComparison.InvariantCultureIgnoreCase));
                    var outputMessage = (
                        hashesMatch
                            ? $"Computed hash MATCH with given hash: {hmacResult.HashString}"
                            : $"Computed hash DOES NOT MATCH with given hash.\nComputed hash: {hmacResult.HashString}\nGiven hash: {hmacOptions.CompareHash}"
                    );
                    Console.WriteLine(outputMessage);

                    return (hashesMatch ? ExitCode.Sucess : ExitCode.Error);
                }
            }
            else if (hmacResult.Success && string.IsNullOrWhiteSpace(hmacOptions.CompareHash))
            {
                Console.WriteLine(hmacResult.HashString);

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(hmacResult.Message);

                return ExitCode.Error;
            }
        }

        private static ExitCode RunArgon2idHashOptionsAndReturnExitCode(Argon2idHashOptions argon2idHashOptions)
        {
            var argon2idHashResult = new Argon2id().ComputeHash(System.Text.Encoding.UTF8.GetBytes(argon2idHashOptions.InputToComputeHash), argon2idHashOptions.Iterations,
                argon2idHashOptions.MemorySize, argon2idHashOptions.DegreeOfParallelism, argon2idHashOptions.AmountBytesToReturn, System.Text.Encoding.UTF8.GetBytes(argon2idHashOptions.Salt),
                System.Text.Encoding.UTF8.GetBytes(argon2idHashOptions.AssociatedData));

            if (argon2idHashResult.Success && !string.IsNullOrWhiteSpace(argon2idHashOptions.CompareHash))
            {
                var hashesMatch = (argon2idHashResult.HashString.Equals(argon2idHashOptions.CompareHash, StringComparison.InvariantCultureIgnoreCase));
                var outputMessage = (
                    hashesMatch
                        ? $"Computed Argon2id hash MATCH with given hash: {argon2idHashResult.HashString}"
                        : $"Computed Argon2id hash DOES NOT MATCH with given hash.\nComputed hash: {argon2idHashResult.HashString}\nGiven hash: {argon2idHashOptions.CompareHash}"
                );
                Console.WriteLine(outputMessage);

                return (hashesMatch ? ExitCode.Sucess : ExitCode.Error);
            }
            else if (argon2idHashResult.Success && string.IsNullOrWhiteSpace(argon2idHashOptions.CompareHash))
            {
                Console.WriteLine(argon2idHashResult.HashString);

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(argon2idHashResult.Message);

                return ExitCode.Error;
            }
        }

        private static ExitCode RunEncodeOptionsAndReturnExitCode(EncodeOptions encodeOptions)
        {
            string encodedString = null;
            string errorMsg = null;

            switch (encodeOptions.EncodeType.ToLower())
            {
                case "base64":
                    {
                        encodedString = Base64.ToBase64String(encodeOptions.InputToEncode);
                    }
                    break;
                case "hex":
                    {
                        encodedString = HighPerformanceHexadecimal.ToHexString(encodeOptions.InputToEncode);
                    }
                    break;
                default:
                    errorMsg = $"Unknown encode type \"{encodeOptions.EncodeType}\".";
                    break;
            }

            if (string.IsNullOrWhiteSpace(errorMsg))
            {
                Console.WriteLine(encodedString);

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(errorMsg);

                return ExitCode.Error;
            }
        }

        private static ExitCode RunDecodeOptionsAndReturnExitCode(DecodeOptions decodeOptions)
        {
            string decodedString = null;
            string errorMsg = null;

            switch (decodeOptions.DecodeType.ToLower())
            {
                case "base64":
                    {
                        decodedString = Base64.ToString(decodeOptions.InputToDecode);
                    }
                    break;
                case "hex":
                    {
                        decodedString = HighPerformanceHexadecimal.ToString(decodeOptions.InputToDecode);
                    }
                    break;
                default:
                    errorMsg = $"Unknown decode type \"{decodeOptions.DecodeType}\".";
                    break;
            }

            if (string.IsNullOrWhiteSpace(errorMsg))
            {
                Console.WriteLine(decodedString);

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(errorMsg);

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
