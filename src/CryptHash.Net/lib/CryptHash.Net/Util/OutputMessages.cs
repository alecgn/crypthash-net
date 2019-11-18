using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CryptHash.Net.Util
{
    public sealed class MessageDictionary
    {
        private static readonly Lazy<MessageDictionary> _lazyMessageDictionary = new Lazy<MessageDictionary>(() => new MessageDictionary());

        private readonly ConcurrentDictionary<string, string> _cdicMessages = new ConcurrentDictionary<string, string>(
            new Dictionary<string, string>() {
                { "Encryption.InputRequired", "Input to encrypt required." },
                { "Encryption.PasswordRequired", "Password to encrypt required." },
                { "Encryption.ExceptionError", "Error while trying to encrypt data:" },

                { "Decryption.InputRequired", "Input to decrypt required." },
                { "Decryption.PasswordRequired", "Password to decrypt required." },
                { "Decryption.ExceptionError", "Error while trying to decrypt data:" },
                { "Decryption.IncorrectInputLengthError", "Incorrect data length, data tampered with." },
                { "Decryption.AuthenticationTagsMismatchError", "Authentication for decryption failed, wrong password or data tampered with." },

                { "Hash.ComputeSuccess", "Input hash computed succesfully." }
            }
        );

        public static MessageDictionary Instance { get { return _lazyMessageDictionary.Value; } }

        private MessageDictionary()
        {
            _cdicMessages = new ConcurrentDictionary<string, string>();
        }

        private string GetMessage(string key)
        {
            string message = $"Unknown key \"{key}\" in Output Messages Dictionary.";
            _cdicMessages.TryGetValue(key, out message);
            
            return message;
        }

        public string this[string key]
        {
            get { return GetMessage(key); }
        }
    }
}
