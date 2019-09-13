using CryptHash.Net.Encryption.AES.AE;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace CryptHash.Net.Tests.Encryption.AES.AE
{
    [TestClass]
    public class AE_AES_256_CBC_HMAC_SHA_512_Tests
    {
        AE_AES_256_CBC_HMAC_SHA_512 _aes256cbc = new AE_AES_256_CBC_HMAC_SHA_512();
        string _testString = "This is a test string!";
        string _password = "P4$$w0rd#123";

        [TestMethod]
        public void Test_EncryptString_with_append_encryption_data()
        {
            var appendEncryptionData = true;

            var aes256cbc_EncryptionResult = _aes256cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            Assert.IsTrue(aes256cbc_EncryptionResult.Success, aes256cbc_EncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptString_without_append_encryption_data()
        {
            var appendEncryptionData = false;

            var aes256cbc_EncryptionResult = _aes256cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            Assert.IsTrue(aes256cbc_EncryptionResult.Success, aes256cbc_EncryptionResult.Message);
        }

        [TestMethod]
        public void Test_DecryptString_with_encryption_data_appended()
        {
            string errorMessage = "";
            var appendEncryptionData = true;
            var aes256cbc_DecryptionResult = new AesEncryptionResult();

            var aes256cbc_EncryptionResult = _aes256cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            if (aes256cbc_EncryptionResult.Success)
            {
                aes256cbc_DecryptionResult = _aes256cbc.DecryptString(aes256cbc_EncryptionResult.EncryptedDataBase64String, _password, hasEncryptionDataAppendedInIntputString: appendEncryptionData);

                if (!aes256cbc_DecryptionResult.Success)
                    errorMessage = aes256cbc_DecryptionResult.Message;
            }
            else
                errorMessage = aes256cbc_EncryptionResult.Message;

            Assert.IsTrue((aes256cbc_EncryptionResult.Success && aes256cbc_DecryptionResult.Success && aes256cbc_DecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_DecryptString_without_encryption_data_appended()
        {
            string errorMessage = "";
            var appendEncryptionData = false;
            var aes256cbc_DecryptionResult = new AesEncryptionResult();

            var aes256cbc_EncryptionResult = _aes256cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            if (aes256cbc_EncryptionResult.Success)
            {
                aes256cbc_DecryptionResult = _aes256cbc.DecryptString(aes256cbc_EncryptionResult.EncryptedDataBytes, Encoding.UTF8.GetBytes(_password),
                    hasEncryptionDataAppendedInIntputString: appendEncryptionData, aes256cbc_EncryptionResult.Tag, aes256cbc_EncryptionResult.Salt, aes256cbc_EncryptionResult.IV);

                if (!aes256cbc_DecryptionResult.Success)
                    errorMessage = aes256cbc_DecryptionResult.Message;
            }
            else
                errorMessage = aes256cbc_EncryptionResult.Message;

            Assert.IsTrue((aes256cbc_EncryptionResult.Success && aes256cbc_DecryptionResult.Success && aes256cbc_DecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }
    }
}
