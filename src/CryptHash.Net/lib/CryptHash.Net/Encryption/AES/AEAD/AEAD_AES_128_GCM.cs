/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.EncryptionResults;
using System.Security;

#if NETSTANDARD2_1
namespace CryptHash.Net.Encryption.AES.AEAD
{
    public class AEAD_AES_128_GCM : AesGcmBase
    {
        #region fields

        private static readonly int _keyBitSize = 128;

        #endregion private fields


        #region constructors

        public AEAD_AES_128_GCM() : base(_keyBitSize) { }

        #endregion constructors


        #region public methods

        #region string encryption

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="plainString">The input plain string to encrypt.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesEncryptionResult EncryptString(string plainString, string password, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            return base.EncryptString(plainString, password, associatedDataString, appendEncryptionDataToOutput);
        }

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="plainString">The input plain string to encrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesEncryptionResult EncryptString(string plainString, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            return base.EncryptString(plainString, secStrPassword, associatedDataString, appendEncryptionDataToOutput);
        }

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided SecureString with the password.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="secStrPassword">The SecureString with the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesEncryptionResult EncryptString(byte[] plainStringBytes, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            return base.EncryptString(plainStringBytes, secStrPassword, associatedDataString, appendEncryptionDataToOutput);
        }

        /// <summary>
        /// Encrypts an input byte array of the string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="plainStringBytes">The input byte array of the string to encrypt.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="associatedData">The byte array of the encryption additional associated data used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="appendEncryptionDataToOutput">Flag to indicate if the encryption additional data required to decrypt will be appended to the output string. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesEncryptionResult EncryptString(byte[] plainStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool appendEncryptionDataToOutput = true)
        {
            return base.EncryptString(plainStringBytes, passwordBytes, associatedData, appendEncryptionDataToOutput);
        }

        #endregion string encryption


        #region string decryption

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="base64EncryptedString">The base64 encoded input string to decrypt.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesDecryptionResult DecryptString(string base64EncryptedString, string password, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            return base.DecryptString(base64EncryptedString, password, associatedDataString, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="base64EncryptedString">The base64 encoded input string to decrypt.</param>
        /// <param name="secStrPassword">The SecureString of the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="tag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="nonce">The previously generated byte array of the Nonce. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesDecryptionResult DecryptString(string base64EncryptedString, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            return base.DecryptString(base64EncryptedString, secStrPassword, associatedDataString, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="encryptedStringBytes">The byte array of the input string to decrypt.</param>
        /// <param name="secStrPassword">The SecureString of the password where the encryption key will be derived from.</param>
        /// <param name="associatedDataString">The encryption additional associated data string used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="tag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="nonce">The previously generated byte array of the Nonce. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesDecryptionResult DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            return base.DecryptString(encryptedStringBytes, secStrPassword, associatedDataString, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        /// <summary>
        /// Decrypts a base64 encoded input string using AES with a 256 bits key in GCM authenticated mode, deriving the key from a provided password string.
        /// </summary>
        /// <param name="encryptedStringBytes">The byte array of the input string to decrypt.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="associatedData">The byte array of the encryption additional associated data used in the authentication process together with the tag. It's not mandatory, leave empty or pass null to not use.</param>
        /// <param name="hasEncryptionDataAppendedInInput">Flag to indicate if the encryption additional data required to decrypt is present in the input base64 encoded encrypted string. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="tag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <param name="nonce">The previously generated byte array of the Nonce. Leave empty or pass null if hasEncryptionDataAppendedInInput = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public new AesDecryptionResult DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            return base.DecryptString(encryptedStringBytes, passwordBytes, associatedData, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        #endregion string decryption

        #endregion public methods
    }
}
#endif