/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptHash.Net.Tests.Hash
{
    [TestClass]
    public class BCrypt_Tests
    {
        private readonly CryptHash.Net.Hash.BCrypt _bcrypt = new CryptHash.Net.Hash.BCrypt();
        private readonly string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String()
        {
            var verifyResult = new GenericHashResult();
            var errorMessage = "";

            var hashResult = _bcrypt.ComputeHash(_testString);

            if (hashResult.Success)
            {
                verifyResult = _bcrypt.VerifyHash(_testString, hashResult.HashString);

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
