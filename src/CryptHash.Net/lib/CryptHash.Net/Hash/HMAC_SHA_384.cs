/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Hash.Base;

namespace CryptHash.Net.Hash
{
    public class HMAC_SHA_384 : HMACBase
    {
        /// <summary>
        /// Computes the HMACSHA384 of an input byte array using a 384 bit key.
        /// </summary>
        /// <param name="bytesToComputeHMAC">The input byte array to compute the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key = null)
        {
            return base.ComputeHMAC(Enums.HashAlgorithm.SHA384, bytesToComputeHMAC, key);
        }

        /// <summary>
        /// Computes the HMACSHA384 of an input string using a 384 bit key.
        /// </summary>
        /// <param name="stringToComputeHMAC">The input string to compute the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeHMAC(string stringToComputeHMAC, byte[] key = null)
        {
            return base.ComputeHMAC(Enums.HashAlgorithm.SHA384, stringToComputeHMAC, key);
        }

        /// <summary>
        /// Computes the HMACSHA384 of an input file using a 384 bit key.
        /// </summary>
        /// <param name="filePathToComputeHMAC">The input file path to compute the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key = null)
        {
            return base.ComputeFileHMAC(Enums.HashAlgorithm.SHA384, filePathToComputeHMAC, key);
        }

        /// <summary>
        /// Verifies the HMACSHA384 of an input byte array using a 384 bit key.
        /// </summary>
        /// <param name="hmacBytes">The pre-computed HMACSHA384 byte array.</param>
        /// <param name="bytesToVerifyHMAC">The input byte array to compute and verify the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyHMAC(byte[] hmacBytes, byte[] bytesToVerifyHMAC, byte[] key)
        {
            return base.VerifyHMAC(Enums.HashAlgorithm.SHA384, hmacBytes, bytesToVerifyHMAC, key);
        }

        /// <summary>
        /// Verifies the HMACSHA384 of an input string using a 384 bit key.
        /// </summary>
        /// <param name="base64HMACString">The pre-computed HMACSHA384 base64 encoded string.</param>
        /// <param name="stringToVerifyHMAC">The input string to compute and verify the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyHMAC(string base64HMACString, string stringToVerifyHMAC, byte[] key)
        {
            return base.VerifyHMAC(Enums.HashAlgorithm.SHA384, base64HMACString, stringToVerifyHMAC, key);
        }

        /// <summary>
        /// Verifies the HMACSHA384 of an input file using a 384 bit key.
        /// </summary>
        /// <param name="base64HMACString">The pre-computed HMACSHA384 base64 encoded string.</param>
        /// <param name="filePathToVerifyHMAC">The input file path to compute and verify the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyFileHMAC(string base64HMACString, string filePathToVerifyHMAC, byte[] key)
        {
            return base.VerifyFileHMAC(Enums.HashAlgorithm.SHA384, base64HMACString, filePathToVerifyHMAC, key);
        }

        /// <summary>
        /// Verifies the HMACSHA384 of an input file using a 384 bit key.
        /// </summary>
        /// <param name="hmacBytes">The pre-computed HMACSHA384 byte array.</param>
        /// <param name="filePathToVerifyHMAC">The input file path to compute and verify the HMACSHA384.</param>
        /// <param name="key">The 384 bit key byte array.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyFileHMAC(byte[] hmacBytes, string filePathToVerifyHMAC, byte[] key)
        {
            return base.VerifyFileHMAC(Enums.HashAlgorithm.SHA384, hmacBytes, filePathToVerifyHMAC, key);
        }
    }
}