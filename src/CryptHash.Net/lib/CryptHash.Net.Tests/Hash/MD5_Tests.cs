/*
 *      Alessandro Cagliostro, 2020
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
    public class MD5_Tests
    {
        MD5 _md5 = new MD5();
        string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String()
        {
            GenericHashResult verifyResult = new GenericHashResult();
            var errorMessage = "";

            var hashResult = _md5.ComputeHash(_testString);

            if (hashResult.Success)
            {
                verifyResult = _md5.VerifyHash(hashResult.HashString, _testString);

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

            var hashResult = _md5.ComputeFileHash(testFilePath);

            if (hashResult.Success)
            {
                verifyResult = _md5.VerifyFileHash(hashResult.HashString, testFilePath);

                if (!verifyResult.Success)
                    errorMessage = verifyResult.Message;
            }
            else
                errorMessage = hashResult.Message;

            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        }
    }
}
