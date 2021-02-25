/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptHash.Net.Tests.Hash
{
    [TestClass]
    public class PBKDF2_HMAC_SHA_1_Tests
    {
        private readonly PBKDF2_HMAC_SHA_1 _pbkdf2HmacSha1 = new PBKDF2_HMAC_SHA_1();
        private readonly string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String()
        {
            var verifyResult = new PBKDF2HashResult();
            var errorMessage = "";

            var hashResult = _pbkdf2HmacSha1.ComputeHash(_testString);

            if (hashResult.Success)
            {
                verifyResult = _pbkdf2HmacSha1.VerifyHash(_testString, hashResult.HashString);

                if (!verifyResult.Success)
                {
                    errorMessage = verifyResult.Message;
                }
            }
            else
            {
                errorMessage = hashResult.Message;
            }

            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        }
    }
}
