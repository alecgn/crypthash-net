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
    public class HMAC_SHA_384_Tests
    {
        private readonly HMAC_SHA_384 _hmacSha384 = new HMAC_SHA_384();
        private readonly string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHMAC_String()
        {
            var verifyResult = new HMACHashResult();
            var errorMessage = "";

            var hmacResult = _hmacSha384.ComputeHMAC(_testString);

            if (hmacResult.Success)
            {
                verifyResult = _hmacSha384.VerifyHMAC(hmacResult.HashString, _testString, hmacResult.Key);

                if (!verifyResult.Success)
                {
                    errorMessage = verifyResult.Message;
                }
            }
            else
            {
                errorMessage = hmacResult.Message;
            }

            Assert.IsTrue((hmacResult.Success && verifyResult.Success), errorMessage);
        }
    }
}
