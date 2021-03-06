﻿/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.AEAD;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptHash.Net.Tests.Encryption.AES.AEAD
{
    [TestClass]
    public class AEAD_AES_128_GCM_Tests
    {
        private readonly AEAD_AES_128_GCM _aes128gcm = new AEAD_AES_128_GCM();
        private readonly string _testString = "This is a test string!";
        private readonly string _password = "P4$$w0rd#123";

        [TestMethod]
        public void Test_EncryptString_without_append_encryption_data_without_associated_data()
        {
            string associatedData = null;
            var appendEncryptionData = false;

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptString_without_append_encryption_data_with_associated_data()
        {
            var associatedData = "0f8fad5b-d9cb-469f-a165-70867728950e";
            var appendEncryptionData = false;

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptString_with_append_encryption_data_without_associated_data()
        {
            string associatedData = null;
            var appendEncryptionData = true;

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptString_with_append_encryption_data_with_associated_data()
        {
            var associatedData = "0f8fad5b-d9cb-469f-a165-70867728950e";
            var appendEncryptionData = true;

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_DecryptString_without_encryption_data_appended_without_associated_data()
        {
            string associatedData = null;
            var appendEncryptionData = false;
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionDataToOutput: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes128gcm.DecryptString(aesEncryptionResult.EncryptedDataBytes, System.Text.Encoding.UTF8.GetBytes(_password), null, hasEncryptionDataAppendedInInput: appendEncryptionData,
                    aesEncryptionResult.Tag, aesEncryptionResult.Salt, aesEncryptionResult.Nonce);

                if (!aesDecryptionResult.Success)
                {
                    errorMessage = aesDecryptionResult.Message;
                }
            }
            else
            {
                errorMessage = aesEncryptionResult.Message;
            }

            Assert.IsTrue((aesEncryptionResult.Success && aesDecryptionResult.Success && aesDecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_DecryptString_without_encryption_data_appended_with_associated_data()
        {
            var associatedData = "0f8fad5b-d9cb-469f-a165-70867728950e";
            var appendEncryptionData = false;
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionDataToOutput: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes128gcm.DecryptString(aesEncryptionResult.EncryptedDataBytes, System.Text.Encoding.UTF8.GetBytes(_password), System.Text.Encoding.UTF8.GetBytes(associatedData), hasEncryptionDataAppendedInInput: appendEncryptionData,
                    aesEncryptionResult.Tag, aesEncryptionResult.Salt, aesEncryptionResult.Nonce);

                if (!aesDecryptionResult.Success)
                {
                    errorMessage = aesDecryptionResult.Message;
                }
            }
            else
            {
                errorMessage = aesEncryptionResult.Message;
            }

            Assert.IsTrue((aesEncryptionResult.Success && aesDecryptionResult.Success && aesDecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_DecryptString_with_encryption_data_appended_without_associated_data()
        {
            string associatedData = null;
            var appendEncryptionData = true;
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionDataToOutput: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes128gcm.DecryptString(aesEncryptionResult.EncryptedDataBase64String, _password, associatedData, hasEncryptionDataAppendedInInput: appendEncryptionData);

                if (!aesDecryptionResult.Success)
                {
                    errorMessage = aesDecryptionResult.Message;
                }
            }
            else
            {
                errorMessage = aesEncryptionResult.Message;
            }

            Assert.IsTrue((aesEncryptionResult.Success && aesDecryptionResult.Success && aesDecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_DecryptString_with_encryption_data_appended_with_associated_data()
        {
            var associatedData = "0f8fad5b-d9cb-469f-a165-70867728950e";
            var appendEncryptionData = true;
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes128gcm.EncryptString(_testString, _password, associatedData, appendEncryptionDataToOutput: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes128gcm.DecryptString(aesEncryptionResult.EncryptedDataBase64String, _password, associatedData, hasEncryptionDataAppendedInInput: appendEncryptionData);

                if (!aesDecryptionResult.Success)
                {
                    errorMessage = aesDecryptionResult.Message;
                }
            }
            else
            {
                errorMessage = aesEncryptionResult.Message;
            }

            Assert.IsTrue((aesEncryptionResult.Success && aesDecryptionResult.Success && aesDecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }
    }
}
