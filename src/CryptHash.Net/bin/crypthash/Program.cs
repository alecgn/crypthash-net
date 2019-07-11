/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System;
using System.Collections.Generic;
using CommandLine;
using CommandLine.Text;
using CryptHash.Net.CLI.CommandLineParser;
using CryptHash.Net.CLI.ConsoleUtil;
using CryptHash.Net.Encryption.AES.AE;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.CLI
{
    class Program
    {
        private static ProgressBar _progressBar = null;
        private static AE_AES_256_CBC_HMAC_SHA_256 _aes = null;
        private static MD5 _md5 = null;
        private static SHA1 _sha1 = null;
        private static SHA256 _sha256 = null;
        private static SHA384 _sha384 = null;
        private static SHA512 _sha512 = null;
        private static Hash.BCrypt _bcrypt = null;

        static void Main(string[] args)
        {
            try
            {
                //_progressBar = new ProgressBar();
                //_aes = new AE_AES_256_CBC_HMAC_SHA_256();
                _aes.OnEncryptionMessage += (msg) => { Console.WriteLine(msg); };
                _aes.OnEncryptionProgress += (percentageDone, message) => { _progressBar?.Report((double)percentageDone / 100); };

                ProcessArgs(args);
            }
            catch (Exception ex)
            {
                ShowErrorMessage(ex.Message);

                Environment.Exit((int)ExitCode.Error);
            }
            finally
            {
                _progressBar?.Dispose();
            }
        }

        private static void ProcessArgs(string[] args)
        {

            var parserResult = Parser.Default.ParseArguments<CryptOptions,
                                                             DecryptOptions,
                                                             HashOptions>(args);

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
                            case "aes":
                                {
                                    _aes = _aes ?? new AE_AES_256_CBC_HMAC_SHA_256();
                                    aesEncryptionResult = _aes.EncryptString(cryptOptions.InputToBeEncrypted, cryptOptions.Password);
                                }
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
                            case "aes":
                                {
                                    _aes = _aes ?? new AE_AES_256_CBC_HMAC_SHA_256();
                                    aesEncryptionResult = _aes.EncryptFile(cryptOptions.InputToBeEncrypted, cryptOptions.OutputFilePath, cryptOptions.Password, cryptOptions.DeleteSourceFile);
                                }
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
                Console.WriteLine((cryptOptions.InputType.ToLower().Equals("string") ? aesEncryptionResult.EncryptedDataBase64String : $"\n\n{aesEncryptionResult.Message}"));

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
            AesEncryptionResult aesDecryptionResult = null;

            switch (decryptOptions.InputType.ToLower())
            {
                case "string":
                    {
                        switch (decryptOptions.Algorithm.ToLower())
                        {
                            case "aes":
                                {
                                    _aes = _aes ?? new AE_AES_256_CBC_HMAC_SHA_256();
                                    aesDecryptionResult = _aes.DecryptString(decryptOptions.InputToBeDecrypted, decryptOptions.Password);
                                }
                                break;
                            default:
                                aesDecryptionResult = new AesEncryptionResult() { Success = false, Message = $"Unknown algorithm \"{decryptOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                case "file":
                    {
                        switch (decryptOptions.Algorithm.ToLower())
                        {
                            case "aes":
                                {
                                    _aes = _aes ?? new AE_AES_256_CBC_HMAC_SHA_256();
                                    aesDecryptionResult = _aes.DecryptFile(decryptOptions.InputToBeDecrypted, decryptOptions.OutputFilePath, decryptOptions.Password, decryptOptions.DeleteEncryptedFile);
                                }
                                break;
                            default:
                                aesDecryptionResult = new AesEncryptionResult() { Success = false, Message = $"Unknown algorithm \"{decryptOptions.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                default:
                    aesDecryptionResult = new AesEncryptionResult() { Success = false, Message = $"Unknown input type \"{decryptOptions.InputType}\"." };
                    break;
            }

            if (aesDecryptionResult.Success)
            {
                Console.WriteLine((decryptOptions.InputType.ToLower().Equals("string") ? aesDecryptionResult.DecryptedDataString : $"\n\n{aesDecryptionResult.Message}"));
                Console.CursorVisible = true;

                return ExitCode.Sucess;
            }
            else
            {
                Console.WriteLine(aesDecryptionResult.Message);

                return ExitCode.Error;
            }
        }

        private static ExitCode RunHashOptionsAndReturnExitCode(HashOptions opts)
        {
            GenericHashResult hashResult = null;

            switch (opts.InputType.ToLower())
            {
                case "string":
                    {
                        switch (opts.Algorithm.ToLower())
                        {
                            case "md5":
                                hashResult = new MD5().HashString(opts.InputToBeHashed);
                                break;
                            case "sha1":
                                hashResult = new SHA1().HashString(opts.InputToBeHashed);
                                break;
                            case "sha256":
                                hashResult = new SHA256().HashString(opts.InputToBeHashed);
                                break;
                            case "sha384":
                                hashResult = new SHA384().HashString(opts.InputToBeHashed);
                                break;
                            case "sha512":
                                hashResult = new SHA512().HashString(opts.InputToBeHashed);
                                break;
                            case "bcrypt":
                                hashResult = new Hash.BCrypt().HashString(opts.InputToBeHashed);
                                break;
                            default:
                                hashResult = new GenericHashResult() { Success = false, Message = $"Unknown algorithm \"{opts.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                case "file":
                    {
                        switch (opts.Algorithm.ToLower())
                        {
                            case "md5":
                                hashResult = new MD5().HashFile(opts.InputToBeHashed);
                                break;
                            case "sha1":
                                hashResult = new SHA1().HashFile(opts.InputToBeHashed);
                                break;
                            case "sha256":
                                hashResult = new SHA256().HashFile(opts.InputToBeHashed);
                                break;
                            case "sha384":
                                hashResult = new SHA384().HashFile(opts.InputToBeHashed);
                                break;
                            case "sha512":
                                hashResult = new SHA512().HashFile(opts.InputToBeHashed);
                                break;
                            case "bcrypt":
                                hashResult = new GenericHashResult() { Success = false, Message = $"Algorithm \"{opts.Algorithm}\" currently not available for file hashing." };
                                break;
                            default:
                                hashResult = new GenericHashResult() { Success = false, Message = $"Unknown algorithm \"{opts.Algorithm}\"." };
                                break;
                        }
                    }
                    break;
                default:
                    hashResult = new GenericHashResult() { Success = false, Message = $"Unknown input type \"{opts.InputType}\"." };
                    break;
            }

            if (hashResult.Success && !string.IsNullOrWhiteSpace(opts.CompareHash))
            {
                bool hashesMatch = (
                    opts.Algorithm.ToLower() != "bcrypt"
                        ? ((string)hashResult.Hash).Equals(opts.CompareHash, StringComparison.InvariantCultureIgnoreCase)
                        : new Hash.BCrypt().Verify(opts.InputToBeHashed, opts.CompareHash).Success
                );
                var outputMessage = (
                    hashesMatch
                        ? $"Computed hash MATCH with given hash: {(opts.Algorithm.ToLower() != "bcrypt" ? (string)hashResult.Hash : opts.CompareHash)}"
                        : $"Computed hash DOES NOT MATCH with given hash." +
                        (
                            opts.Algorithm.ToLower() != "bcrypt"
                                ? $"\nComputed hash: {(string)hashResult.Hash}\nGiven hash: {opts.CompareHash}"
                                : ""
                        )
                );

                Console.WriteLine(outputMessage);

                return (hashesMatch ? ExitCode.Sucess : ExitCode.Error);
            }
            else if (hashResult.Success && string.IsNullOrWhiteSpace(opts.CompareHash))
            {
                Console.WriteLine(hashResult.Hash);

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
            Console.WriteLine("An error has occured during processing:\n");
            Console.WriteLine(errorMessage);
        }
    }
}
