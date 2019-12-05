/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Base;
using CryptHash.Net.Hash.HashResults;

namespace CryptHash.Net.Hash.Hash
{
    public class MD5 : HashBase
    {
        /// <summary>
        /// Computes the MD5 hash of an input byte array.
        /// </summary>
        /// <param name="bytesToComputeHash">The input byte array to compute the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.MD5, bytesToComputeHash);
        }

        /// <summary>
        /// Computes the MD5 hash of an input string.
        /// </summary>
        /// <param name="stringToComputeHash">The input string to compute the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(Enums.HashAlgorithm.MD5, stringToComputeHash);
        }

        /// <summary>
        /// Computes the MD5 hash of an input file.
        /// </summary>
        /// <param name="filePathToComputeHash">The input file path to compute the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeFileHash(string filePathToComputeHash)
        {
            return base.ComputeFileHash(Enums.HashAlgorithm.MD5, filePathToComputeHash);
        }


        /// <summary>
        /// Verifies the MD5 hash of an input byte array.
        /// </summary>
        /// <param name="hashBytes">The pre-computed MD5 hash byte array.</param>
        /// <param name="bytesToVerifyHash">The input byte array to compute and verify the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.MD5, hashBytes, bytesToVerifyHash);
        }

        /// <summary>
        /// Verifies the MD5 hash of an input string.
        /// </summary>
        /// <param name="hashHexString">The pre-computed MD5 hash hexadecimal encoded string.</param>
        /// <param name="stringToVerifyHash">The input string to compute and verify the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(string hashHexString, string stringToVerifyHash)
        {
            return base.VerifyHash(Enums.HashAlgorithm.MD5, hashHexString, stringToVerifyHash);
        }

        /// <summary>
        /// Verifies the MD5 of an input file.
        /// </summary>
        /// <param name="hashHexString">The pre-computed MD5 hash hexadecimal encoded string.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(string hashHexString, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.MD5, hashHexString, filePathToVerifyHash);
        }

        /// <summary>
        /// Verifies the MD5 of an input file.
        /// </summary>
        /// <param name="hashBytes">The pre-computed MD5 hash byte array.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the MD5 hash.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash)
        {
            return base.VerifyFileHash(Enums.HashAlgorithm.MD5, hashBytes, filePathToVerifyHash);
        }
    }
}
