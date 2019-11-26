using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace CryptHash.Net.Util
{
    public sealed class MessageDictionary
    {
        private static readonly Lazy<MessageDictionary> _lazyMessageDictionary = new Lazy<MessageDictionary>(() => new MessageDictionary());

        private readonly IDictionary<string, string> _cdicMessages = new ConcurrentDictionary<string, string>()
        {
            ["Common.FileNotFound"] = "File not found:",
            ["Common.AlgorithmNotSupported"] = $"Algorithm not supported:",
            ["Common.InvalidKeySizeError"] = "Invalid key bit size:",
            ["Common.InvalidAuthKeySizeError"] = "Invalid auth key bit size:",
            ["Common.IncorrectInputLengthError"] = "Incorrect data length, data probably tampered with.",
            ["Common.InvalidDataLengthError"] = "Invalid data length: ",
            ["Common.IncorrectTagsLength"] = "Tags length must be equal.",
            ["Common.IncorrectHexadecimalString"] = "Incorret hexadecimal string.",

            ["Encryption.InputRequired"] = "Input to encrypt required.",
            ["Encryption.PasswordRequired"] = "Password to encrypt required.",
            ["Encryption.ExceptionError"] = "Error while trying to encrypt data:",
            ["Encryption.FileAdditionalDataWriting"] = "Writing additional data to file...",
            ["Encryption.FileAdditionalDataWritten"] = "Additional data written to file.",
            ["Encryption.MaxInputSizeError"] = "Max. input size cannot be greater in bytes than:",
            ["Encryption.MaxAssociatedDataSizeError"] = "Max. associated data size cannot be greater in bytes than:",
            ["Encryption.EncryptSuccess"] = "Data succesfully encrypted.",
            ["Encryption.EncryptedFilePathError"] = "Encrypted file path required.",
            ["Encryption.DestinationDirectoryNotFound"] = "Destination directory not found:",
            ["Encryption.FileEncryptSuccess"] = "File \"{0}\" successfully encrypted to \"{1}\".",
            ["Encryption.FileDeleted"] = "File \"{0}\" deleted.",

            ["Decryption.InputRequired"] = "Input to decrypt required.",
            ["Decryption.PasswordRequired"] = "Password to decrypt required.",
            ["Decryption.ExceptionError"] = "Error while trying to decrypt data:",
            ["Decryption.AuthenticationTagsMismatchError"] = "Authentication for decryption failed, wrong password or data probably tampered with.",
            ["Decryption.EncryptedFileNotFound"] = "Encrypted file not found:",
            ["Decryption.MaxEncryptedInputSizeError"] = "Max. encrypted input size cannot be greater in bytes than:",
            ["Decryption.DecryptSuccess"] = "Data succesfully decrypted.",
            ["Decryption.NullKeyError"] = "Key cannot be null.",
            ["Decryption.NullIVError"] = "IV cannot be null.",
            ["Decryption.DecryptedFilePathError"] = "Decrypted file path required.",
            ["Decryption.EndPositionLessThanStartError"] = "End position (\"{0}\") cannot be less than start position (\"{1}\").",
            ["Decryption.FileDecryptSuccess"] = "File \"{0}\" successfully decrypted to \"{1}\".",

            ["Hash.ComputeSuccess"] = "Input hash computed succesfully.",
            ["Hash.InputRequired"] = "Input to compute hash required.",
            ["Hash.VerificationHashRequired"] = "Verification hash required.",
            ["Hash.Match"] = "Input hash and verification hash match.",
            ["Hash.DoesNotMatch"] = "Input hash and verification hash does not match.",

            ["HMAC.InputRequired"] = "Input to compute HMAC required.",
            ["HMAC.ComputeSuccess"] = "Input HMAC computed succesfully.",
        };

        public static MessageDictionary Instance { get { return _lazyMessageDictionary.Value; } }

        private MessageDictionary() { }

        private string GetMessage(string key)
        {
            string message;

            if (!_cdicMessages.TryGetValue(key, out message))
                message = $"Unknown key \"{key}\" in OutputMessages Dictionary.\nAvailable keys: ({string.Join(", ", _cdicMessages.Select(i => $"\"{i.Key}\""))}).";

            return message;
        }

        public string this[string key]
        {
            get { return GetMessage(key); }
        }
    }
}
