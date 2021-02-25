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
    public class Argon2id_Tests
    {
        private readonly Argon2id _argon2id = new Argon2id();
        private readonly string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String_without_associated_data()
        {
            var verifyResult = new Argon2idHashResult();
            var errorMessage = "";

            var testStringBytes = System.Text.Encoding.UTF8.GetBytes(_testString);
            var iterations = 4;
            var kbMemorySize = 1024;
            var degreeOfParallelism = 0; // auto-generate based on number of the processor's cores
            var amountBytesToReturn = 16;
            byte[] salt = null; // auto-generate
            byte[] associatedData = null;
            byte[] knownSecret = null;

            var hashResult = _argon2id.ComputeHash(testStringBytes, iterations, kbMemorySize, degreeOfParallelism, amountBytesToReturn, salt,
                associatedData, knownSecret);

            if (hashResult.Success)
            {
                verifyResult = _argon2id.VerifyHash(hashResult.HashBytes, testStringBytes, iterations, kbMemorySize, degreeOfParallelism,
                    amountBytesToReturn, hashResult.SaltBytes, associatedData, knownSecret);

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

        [TestMethod]
        public void ComputeAndVerifyHash_String_with_associated_data()
        {
            var verifyResult = new Argon2idHashResult();
            var errorMessage = "";

            var testStringBytes = System.Text.Encoding.UTF8.GetBytes(_testString);
            var iterations = 4;
            var kbMemorySize = 1024;
            var degreeOfParallelism = 0; // auto-generate based on number of the processor's cores
            var amountBytesToReturn = 16;
            byte[] salt = null; // auto-generate
            var associatedData = System.Text.Encoding.UTF8.GetBytes("0f8fad5b-d9cb-469f-a165-70867728950e");
            byte[] knownSecret = null;

            var hashResult = _argon2id.ComputeHash(testStringBytes, iterations, kbMemorySize, degreeOfParallelism, amountBytesToReturn, salt,
                associatedData, knownSecret);

            if (hashResult.Success)
            {
                verifyResult = _argon2id.VerifyHash(hashResult.HashBytes, testStringBytes, iterations, kbMemorySize, degreeOfParallelism,
                    amountBytesToReturn, hashResult.SaltBytes, associatedData, knownSecret);

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
