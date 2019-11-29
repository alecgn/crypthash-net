/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class SHA384 : HashBase
    {
        /// <summary>
        /// Computes the SHA384 hash of an input byte array.
        /// </summary>
        /// <param name="bytesToComputeHash">The input byte array to compute the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA384, bytesToComputeHash);
        }

        /// <summary>
        /// Computes the SHA384 hash of an input string.
        /// </summary>
        /// <param name="stringToComputeHash">The input string to compute the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA384, stringToComputeHash);
        }

        /// <summary>
        /// Computes the SHA384 hash of an input file.
        /// </summary>
        /// <param name="filePathToComputeHash">The input file path to compute the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeFileHash(string filePathToComputeHash)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.SHA384, filePathToComputeHash);
        }

        /// <summary>
        /// Verifies the SHA384 hash of an input byte array.
        /// </summary>
        /// <param name="hashBytes">The pre-computed SHA384 hash byte array.</param>
        /// <param name="bytesToVerifyHash">The input byte array to compute and verify the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA384, hashBytes, bytesToVerifyHash);
        }

        /// <summary>
        /// Verifies the SHA384 hash of an input string.
        /// </summary>
        /// <param name="base64HashString">The pre-computed SHA384 hash base64 encoded string.</param>
        /// <param name="stringToVerifyHash">The input string to compute and verify the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(string base64HashString, string stringToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA384, base64HashString, stringToVerifyHash);
        }

        /// <summary>
        /// Verifies the SHA384 of an input file.
        /// </summary>
        /// <param name="base64HashString">The pre-computed SHA384 hash base64 encoded string.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(string base64HashString, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA384, base64HashString, filePathToVerifyHash);
        }

        /// <summary>
        /// Verifies the SHA384 of an input file.
        /// </summary>
        /// <param name="hashBytes">The pre-computed SHA384 hash byte array.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the SHA384 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA384, hashBytes, filePathToVerifyHash);
        }
    }
}
