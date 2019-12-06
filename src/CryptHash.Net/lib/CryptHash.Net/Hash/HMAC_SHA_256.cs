/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Hash.Base;

namespace CryptHash.Net.Hash
{
    public class HMAC_SHA_256 : HMACBase
    {
        /// <summary>
        /// Computes the HMACSHA256 of an input byte array using a 256 bit key.
        /// </summary>
        /// <param name="bytesToComputeHMAC">The input byte array to compute the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key = null, int offset = 0, int count = 0)
        {
            return base.ComputeHMAC(Enums.HMACAlgorithm.HMACSHA256, bytesToComputeHMAC, key, offset, count);
        }

        /// <summary>
        /// Computes the HMACSHA256 of an input string using a 256 bit key.
        /// </summary>
        /// <param name="stringToComputeHMAC">The input string to compute the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeHMAC(string stringToComputeHMAC, byte[] key = null, int offset = 0, int count = 0)
        {
            return base.ComputeHMAC(Enums.HMACAlgorithm.HMACSHA256, stringToComputeHMAC, key, offset, count);
        }

        /// <summary>
        /// Computes the HMACSHA256 of an input file using a 256 bit key.
        /// </summary>
        /// <param name="filePathToComputeHMAC">The input file path to compute the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key = null, long offset = 0, long count = 0)
        {
            return base.ComputeFileHMAC(Enums.HMACAlgorithm.HMACSHA256, filePathToComputeHMAC, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACSHA256 of an input byte array using a 256 bit key.
        /// </summary>
        /// <param name="hmacBytes">The pre-computed HMACSHA256 byte array.</param>
        /// <param name="bytesToVerifyHMAC">The input byte array to compute and verify the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyHMAC(byte[] hmacBytes, byte[] bytesToVerifyHMAC, byte[] key, int offset = 0, int count = 0)
        {
            return base.VerifyHMAC(Enums.HMACAlgorithm.HMACSHA256, hmacBytes, bytesToVerifyHMAC, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACSHA256 of an input string using a 256 bit key.
        /// </summary>
        /// <param name="hmacHexString">The pre-computed HMACSHA256 hexadecimal encoded string.</param>
        /// <param name="stringToVerifyHMAC">The input string to compute and verify the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyHMAC(string hmacHexString, string stringToVerifyHMAC, byte[] key, int offset = 0, int count = 0)
        {
            return base.VerifyHMAC(Enums.HMACAlgorithm.HMACSHA256, hmacHexString, stringToVerifyHMAC, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACSHA256 of an input file using a 256 bit key.
        /// </summary>
        /// <param name="hmacHexString">The pre-computed HMACSHA256 hexadecimal encoded string.</param>
        /// <param name="filePathToVerifyHMAC">The input file path to compute and verify the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyFileHMAC(string hmacHexString, string sourceFilePath, byte[] key, long offset = 0, long count = 0)
        {
            return base.VerifyFileHMAC(Enums.HMACAlgorithm.HMACSHA256, hmacHexString, sourceFilePath, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACSHA256 of an input file using a 256 bit key.
        /// </summary>
        /// <param name="hmacBytes">The pre-computed HMACSHA256 byte array.</param>
        /// <param name="filePathToVerifyHMAC">The input file path to compute and verify the HMACSHA256.</param>
        /// <param name="key">The 256 bit key byte array.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyFileHMAC(byte[] hmacBytes, string sourceFilePath, byte[] key, long offset = 0, long count = 0)
        {
            return base.VerifyFileHMAC(Enums.HMACAlgorithm.HMACSHA256, hmacBytes, sourceFilePath, key, offset, count);
        }
    }
}