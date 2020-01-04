/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Hash.Base;

namespace CryptHash.Net.Hash
{
    public class HMAC_MD5 : HMACBase
    {
        /// <summary>
        /// Computes the HMACMD5 of an input byte array using a key.
        /// </summary>
        /// <param name="bytesToComputeHMAC">The input byte array to compute the HMAC.</param>
        /// <param name="key">The input key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key = null, int offset = 0, int count = 0)
        {
            return base.ComputeHMAC(Enums.HMACAlgorithm.HMACMD5, bytesToComputeHMAC, key, offset, count);
        }

        /// <summary>
        /// Computes the HMACMD5 of an input string using a key.
        /// </summary>
        /// <param name="stringToComputeHMAC">The input string to compute the HMAC.</param>
        /// <param name="key">The input key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeHMAC(string stringToComputeHMAC, byte[] key = null, int offset = 0, int count = 0)
        {
            return base.ComputeHMAC(Enums.HMACAlgorithm.HMACMD5, stringToComputeHMAC, key, offset, count);
        }

        /// <summary>
        /// Computes the HMACMD5 of an input file using a key.
        /// </summary>
        /// <param name="filePathToComputeHMAC">The input file path to compute the HMAC.</param>
        /// <param name="key">The input key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key = null, long offset = 0, long count = 0)
        {
            return base.ComputeFileHMAC(Enums.HMACAlgorithm.HMACMD5, filePathToComputeHMAC, key, offset, count);
        }


        /// <summary>
        /// Verifies the HMACMD5 of an input byte array using a key.
        /// </summary>
        /// <param name="hmacBytes">The pre-computed HMACMD5 byte array.</param>
        /// <param name="bytesToVerifyHMAC">The input byte array to compute and verify the HMACMD5.</param>
        /// <param name="key">The input key byte array.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyHMAC(byte[] hmacBytes, byte[] bytesToVerifyHMAC, byte[] key, int offset = 0, int count = 0)
        {
            return base.VerifyHMAC(Enums.HMACAlgorithm.HMACMD5, hmacBytes, bytesToVerifyHMAC, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACMD5 of an input string using a key.
        /// </summary>
        /// <param name="hmacHexString">The pre-computed HMACMD5 hexadecimal encoded string.</param>
        /// <param name="stringToVerifyHMAC">The input string to compute and verify the HMACMD5.</param>
        /// <param name="key">The input key byte array.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyHMAC(string hmacHexString, string stringToVerifyHMAC, byte[] key, int offset = 0, int count = 0)
        {
            return base.VerifyHMAC(Enums.HMACAlgorithm.HMACMD5, hmacHexString, stringToVerifyHMAC, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACMD5 of an input file using a key.
        /// </summary>
        /// <param name="hmacHexString">The pre-computed HMACMD5 hexadecimal encoded string.</param>
        /// <param name="filePathToVerifyHMAC">The input file path to compute and verify the HMACMD5.</param>
        /// <param name="key">The input key byte array.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyFileHMAC(string hmacHexString, string filePathToVerifyHMAC, byte[] key, long offset = 0, long count = 0)
        {
            return base.VerifyFileHMAC(Enums.HMACAlgorithm.HMACMD5, hmacHexString, filePathToVerifyHMAC, key, offset, count);
        }

        /// <summary>
        /// Verifies the HMACMD5 of an input file using a key.
        /// </summary>
        /// <param name="hmacBytes">The pre-computed HMACMD5 byte array.</param>
        /// <param name="filePathToVerifyHMAC">The input file path to compute and verify the HMACMD5.</param>
        /// <param name="key">The input key byte array.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HMACHashResult VerifyFileHMAC(byte[] hmacBytes, string filePathToVerifyHMAC, byte[] key, long offset = 0, long count = 0)
        {
            return base.VerifyFileHMAC(Enums.HMACAlgorithm.HMACMD5, hmacBytes, filePathToVerifyHMAC, key, offset, count);
        }
    }
}