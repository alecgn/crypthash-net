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
    public class SHA384_Tests
    {
        private readonly SHA384 _sha384 = new SHA384();
        private readonly string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String()
        {
            var verifyResult = new GenericHashResult();
            var errorMessage = "";

            var hashResult = _sha384.ComputeHash(_testString);

            if (hashResult.Success)
            {
                verifyResult = _sha384.VerifyHash(hashResult.HashString, _testString);

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

            var hashResult = _sha384.ComputeFileHash(testFilePath);

            if (hashResult.Success)
            {
                verifyResult = _sha384.VerifyFileHash(hashResult.HashString, testFilePath);

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
