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
                ["Encryption.InputRequired"] = "Input to encrypt required." ,
                ["Encryption.PasswordRequired"]  = "Password to encrypt required.",
                ["Encryption.ExceptionError"] = "Error while trying to encrypt data:",
                ["Encryption.FileAdditionalDataWriting"] = "Writing additional data to file...",
                ["Encryption.FileAdditionalDataWritten"] = "Additional data written to file.",
                ["Decryption.InputRequired"] = "Input to decrypt required.",
                ["Decryption.PasswordRequired"] = "Password to decrypt required.",
                ["Decryption.ExceptionError"] = "Error while trying to decrypt data:",
                ["Decryption.IncorrectInputLengthError"] = "Incorrect data length, data probably tampered with.",
                ["Decryption.AuthenticationTagsMismatchError"] = "Authentication for decryption failed, wrong password or data probably tampered with.",
                ["Decryption.EncryptedFileNotFound"] = "Encrypted file not found:",
                ["Hash.ComputeSuccess"] = "Input hash computed succesfully."
        };

        public static MessageDictionary Instance { get { return _lazyMessageDictionary.Value; } }

        private MessageDictionary()
        {
            //_cdicMessages = new ConcurrentDictionary<string, string>();
        }

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
