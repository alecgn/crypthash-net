/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Encryption.AES.AE;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace CryptHash.Net.Tests.Encryption.AES.AE
{
    [TestClass]
    public class AE_AES_256_CBC_HMAC_SHA_384_Tests
    {
        private readonly AE_AES_256_CBC_HMAC_SHA_384 _aes256cbcHmacSha384 = new AE_AES_256_CBC_HMAC_SHA_384();
        private readonly string _testString = "This is a test string!";
        private readonly string _password = "P4$$w0rd#123";

        [TestMethod]
        public void Test_EncryptString_with_append_encryption_data()
        {
            var appendEncryptionData = true;

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptString(_testString, _password, appendEncryptionDataToOutput: appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptString_without_append_encryption_data()
        {
            var appendEncryptionData = false;

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptString(_testString, _password, appendEncryptionDataToOutput: appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_DecryptString_with_encryption_data_appended()
        {
            var appendEncryptionData = true;
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptString(_testString, _password, appendEncryptionDataToOutput: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes256cbcHmacSha384.DecryptString(aesEncryptionResult.EncryptedDataBase64String, _password, hasEncryptionDataAppendedInInput: appendEncryptionData);

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
        public void Test_DecryptString_without_encryption_data_appended()
        {
            var appendEncryptionData = false;
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptString(_testString, _password, appendEncryptionDataToOutput: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes256cbcHmacSha384.DecryptString(aesEncryptionResult.EncryptedDataBytes, System.Text.Encoding.UTF8.GetBytes(_password),
                    hasEncryptionDataAppendedInInput: appendEncryptionData, aesEncryptionResult.Tag, aesEncryptionResult.Salt, aesEncryptionResult.IV);

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
        public void Test_EncryptFile_with_append_encryption_data()
        {
            var testFilePath = Path.GetTempFileName();
            var appendEncryptionData = true;

            File.WriteAllText(testFilePath, _testString);

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptFile(testFilePath, testFilePath, _password, false, appendEncryptionDataToOutputFile: appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptFile_without_append_encryption_data()
        {
            var testFilePath = Path.GetTempFileName();
            var appendEncryptionData = false;

            File.WriteAllText(testFilePath, _testString);

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptFile(testFilePath, testFilePath, _password, false, appendEncryptionDataToOutputFile: appendEncryptionData);

            Assert.IsTrue(aesEncryptionResult.Success, aesEncryptionResult.Message);
        }

        [TestMethod]
        public void Test_DecryptFile_with_append_encryption_data()
        {
            var testFilePath = Path.GetTempFileName();
            var appendEncryptionData = true;
            var aesDecryptionResult = new AesDecryptionResult();
            var testFileStringContentRead = "";
            var errorMessage = "";

            File.WriteAllText(testFilePath, _testString);

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptFile(testFilePath, testFilePath, _password, false, appendEncryptionDataToOutputFile: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes256cbcHmacSha384.DecryptFile(testFilePath, testFilePath, _password, false, hasEncryptionDataAppendedInInputFile: appendEncryptionData);

                if (aesDecryptionResult.Success)
                {
                    testFileStringContentRead = File.ReadAllText(testFilePath);
                }
                else
                {
                    errorMessage = aesDecryptionResult.Message;
                }
            }
            else
            {
                errorMessage = aesEncryptionResult.Message;
            }

            Assert.IsTrue((aesEncryptionResult.Success && aesDecryptionResult.Success && testFileStringContentRead.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_DecryptFile_without_append_encryption_data()
        {
            var testFilePath = Path.GetTempFileName();
            var appendEncryptionData = false;
            var aesDecryptionResult = new AesDecryptionResult();
            var testFileStringContentRead = "";
            var errorMessage = "";

            File.WriteAllText(testFilePath, _testString);

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptFile(testFilePath, testFilePath, _password, false, appendEncryptionDataToOutputFile: appendEncryptionData);

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes256cbcHmacSha384.DecryptFile(testFilePath, testFilePath, System.Text.Encoding.UTF8.GetBytes(_password), false, hasEncryptionDataAppendedInInputFile: appendEncryptionData,
                    aesEncryptionResult.Tag, aesEncryptionResult.Salt, aesEncryptionResult.IV);

                if (aesDecryptionResult.Success)
                {
                    testFileStringContentRead = File.ReadAllText(testFilePath);
                }
                else
                {
                    errorMessage = aesDecryptionResult.Message;
                }
            }
            else
            {
                errorMessage = aesEncryptionResult.Message;
            }

            Assert.IsTrue((aesEncryptionResult.Success && aesDecryptionResult.Success && testFileStringContentRead.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_Encrypt_Decrypt_String_without_password()
        {
            var aesDecryptionResult = new AesDecryptionResult();
            var errorMessage = "";

            var aesEncryptionResult = _aes256cbcHmacSha384.EncryptString(System.Text.Encoding.UTF8.GetBytes(_testString));

            if (aesEncryptionResult.Success)
            {
                aesDecryptionResult = _aes256cbcHmacSha384.DecryptString(aesEncryptionResult.EncryptedDataBytes, aesEncryptionResult.Key, aesEncryptionResult.IV,
                    aesEncryptionResult.AuthenticationKey, aesEncryptionResult.Tag);

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
