using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace CryptHash.Net.Tests.Hash
{
    [TestClass]
    public class Argon2id_Tests
    {
        Argon2id _argon2id = new Argon2id();
        string _testString = "This is a test string!";

        [TestMethod]
        public void ComputeAndVerifyHash_String_without_associated_data()
        {
            Argon2idHashResult verifyResult = new Argon2idHashResult();
            var errorMessage = "";

            byte[] testStringBytes = Encoding.UTF8.GetBytes(_testString);
            int iterations = 4;
            int kbMemorySize = 1024;
            int degreeOfParallelism = 0; // auto-generate based on number of the processor's cores
            int amountBytesToReturn = 16;
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
                    errorMessage = verifyResult.Message;
            }
            else
                errorMessage = hashResult.Message;


            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        }

        [TestMethod]
        public void ComputeAndVerifyHash_String_with_associated_data()
        {
            Argon2idHashResult verifyResult = new Argon2idHashResult();
            var errorMessage = "";

            byte[] testStringBytes = Encoding.UTF8.GetBytes(_testString);
            int iterations = 4;
            int kbMemorySize = 1024;
            int degreeOfParallelism = 0; // auto-generate based on number of the processor's cores
            int amountBytesToReturn = 16;
            byte[] salt = null; // auto-generate
            byte[] associatedData = Encoding.UTF8.GetBytes("0f8fad5b-d9cb-469f-a165-70867728950e");
            byte[] knownSecret = null;

            var hashResult = _argon2id.ComputeHash(testStringBytes, iterations, kbMemorySize, degreeOfParallelism, amountBytesToReturn, salt,
                associatedData, knownSecret);

            if (hashResult.Success)
            {
                verifyResult = _argon2id.VerifyHash(hashResult.HashBytes, testStringBytes, iterations, kbMemorySize, degreeOfParallelism,
                    amountBytesToReturn, hashResult.SaltBytes, associatedData, knownSecret);

                if (!verifyResult.Success)
                    errorMessage = verifyResult.Message;
            }
            else
                errorMessage = hashResult.Message;


            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        }
    }
}
