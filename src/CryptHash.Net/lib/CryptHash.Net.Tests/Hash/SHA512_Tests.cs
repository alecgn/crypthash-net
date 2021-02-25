/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace CryptHash.Net.Tests.Hash
{
    [TestClass]
    public class SHA512_Tests
    {
        private readonly SHA512 _sha512 = new SHA512();
        private readonly string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String()
        {
            var verifyResult = new GenericHashResult();
            var errorMessage = "";

            var hashResult = _sha512.ComputeHash(_testString);

            if (hashResult.Success)
            {
                verifyResult = _sha512.VerifyHash(hashResult.HashString, _testString);

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

        public void ComputeAndVerifyHash_File()
        {
            var testFilePath = Path.GetTempFileName();
            var verifyResult = new GenericHashResult();
            var errorMessage = "";

            File.WriteAllText(testFilePath, _testString);

            var hashResult = _sha512.ComputeFileHash(testFilePath);

            if (hashResult.Success)
            {
                verifyResult = _sha512.VerifyFileHash(hashResult.HashString, testFilePath);

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
