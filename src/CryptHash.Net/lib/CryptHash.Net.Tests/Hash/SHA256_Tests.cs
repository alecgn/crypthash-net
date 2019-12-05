using CryptHash.Net.Hash.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace CryptHash.Net.Tests.Hash
{
    [TestClass]
    public class SHA256_Tests
    {
        SHA256 _sha256 = new SHA256();
        string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String()
        {
            GenericHashResult verifyResult = new GenericHashResult();
            var errorMessage = "";

            var hashResult = _sha256.ComputeHash(_testString);

            if (hashResult.Success)
            {
                verifyResult = _sha256.VerifyHash(hashResult.HashString, _testString);

                if (!verifyResult.Success)
                    errorMessage = verifyResult.Message;
            }
            else
                errorMessage = hashResult.Message;


            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        }

        [TestMethod]
        public void ComputeAndVerifyHash_File()
        {
            var testFilePath = Path.GetTempFileName();
            GenericHashResult verifyResult = new GenericHashResult();
            var errorMessage = "";

            File.WriteAllText(testFilePath, _testString);

            var hashResult = _sha256.ComputeFileHash(testFilePath);

            if (hashResult.Success)
            {
                verifyResult = _sha256.VerifyFileHash(hashResult.HashString, testFilePath);

                if (!verifyResult.Success)
                    errorMessage = verifyResult.Message;
            }
            else
                errorMessage = hashResult.Message;

            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        }
    }
}
