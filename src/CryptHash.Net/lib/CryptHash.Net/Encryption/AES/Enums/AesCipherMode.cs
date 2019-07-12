/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using System.Security.Cryptography;

namespace CryptHash.Net.Encryption.AES.Enums
{
    public enum AesCipherMode { CBC = CipherMode.CBC, ECB = CipherMode.ECB, OFB = CipherMode.OFB, CFB = CipherMode.CFB, CTS = CipherMode.CTS };
}
