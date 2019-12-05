using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptHash.Net.Tests.Hash
{
    [TestClass]
    public class HMAC_MD5_Tests
    {
        HMAC_MD5 _hmacMd5 = new HMAC_MD5();
        string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHMAC_String()
        {
            HMACHashResult verifyResult = new HMACHashResult();
            var errorMessage = "";

            var hmacResult = _hmacMd5.ComputeHMAC(_testString);

            if (hmacResult.Success)
            {
                verifyResult = _hmacMd5.VerifyHMAC(hmacResult.HashString, _testString, hmacResult.Key);

                if (!verifyResult.Success)
                    errorMessage = verifyResult.Message;
            }
            else
                errorMessage = hmacResult.Message;


            Assert.IsTrue((hmacResult.Success && verifyResult.Success), errorMessage);
        }
    }
}
