/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class SHA512 : HashBase
    {
        /// <summary>
        /// Computes the SHA512 hash of an input byte array.
        /// </summary>
        /// <param name="bytesToComputeHash">The input byte array to compute the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA512, bytesToComputeHash);
        }

        /// <summary>
        /// Computes the SHA512 hash of an input string.
        /// </summary>
        /// <param name="stringToComputeHash">The input string to compute the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.SHA512, stringToComputeHash);
        }

        /// <summary>
        /// Computes the SHA512 hash of an input file.
        /// </summary>
        /// <param name="filePathToComputeHash">The input file path to compute the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeFileHash(string filePathToComputeHash)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.SHA512, filePathToComputeHash);
        }

        /// <summary>
        /// Verifies the SHA512 hash of an input byte array.
        /// </summary>
        /// <param name="hashBytes">The pre-computed SHA512 hash byte array.</param>
        /// <param name="bytesToVerifyHash">The input byte array to compute and verify the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA512, hashBytes, bytesToVerifyHash);
        }

        /// <summary>
        /// Verifies the SHA512 hash of an input string.
        /// </summary>
        /// <param name="hashHexString">The pre-computed SHA512 hash hexadecimal encoded string.</param>
        /// <param name="stringToVerifyHash">The input string to compute and verify the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(string hashHexString, string stringToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.SHA512, hashHexString, stringToVerifyHash);
        }

        /// <summary>
        /// Verifies the SHA512 of an input file.
        /// </summary>
        /// <param name="hashHexString">The pre-computed SHA512 hash hexadecimal encoded string.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(string hashHexString, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA512, hashHexString, filePathToVerifyHash);
        }

        /// <summary>
        /// Verifies the SHA512 of an input file.
        /// </summary>
        /// <param name="hashBytes">The pre-computed SHA512 hash byte array.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the SHA512 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.SHA512, hashBytes, filePathToVerifyHash);
        }
    }
}
