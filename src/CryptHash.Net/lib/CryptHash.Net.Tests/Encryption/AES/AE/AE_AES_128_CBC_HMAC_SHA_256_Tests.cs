using CryptHash.Net.Encryption.AES.AE;
using CryptHash.Net.Encryption.AES.EncryptionResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace CryptHash.Net.Tests.Encryption.AES.AE
{
    [TestClass]
    public class AE_AES_128_CBC_HMAC_SHA_256_Tests
    {
        AE_AES_128_CBC_HMAC_SHA_256 _aes128cbc = new AE_AES_128_CBC_HMAC_SHA_256();
        string _testString = "This is a test string!";
        string _password = "P4$$w0rd#123";

        [TestMethod]
        public void Test_EncryptString_with_append_encryption_data()
        {
            var appendEncryptionData = true;

            var aes128cbc_EncryptionResult = _aes128cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            Assert.IsTrue(aes128cbc_EncryptionResult.Success, aes128cbc_EncryptionResult.Message);
        }

        [TestMethod]
        public void Test_EncryptString_without_append_encryption_data()
        {
            var appendEncryptionData = false;

            var aes128cbc_EncryptionResult = _aes128cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            Assert.IsTrue(aes128cbc_EncryptionResult.Success, aes128cbc_EncryptionResult.Message);
        }

        [TestMethod]
        public void Test_DecryptString_with_encryption_data_appended()
        {
            string errorMessage = "";
            var appendEncryptionData = true;
            var aes128cbc_DecryptionResult = new AesEncryptionResult();

            var aes128cbc_EncryptionResult = _aes128cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            if (aes128cbc_EncryptionResult.Success)
            {
                aes128cbc_DecryptionResult = _aes128cbc.DecryptString(aes128cbc_EncryptionResult.EncryptedDataBase64String, _password, hasEncryptionDataAppendedInIntputString: appendEncryptionData);

                if (!aes128cbc_DecryptionResult.Success)
                    errorMessage = aes128cbc_DecryptionResult.Message;
            }
            else
                errorMessage = aes128cbc_EncryptionResult.Message;

            Assert.IsTrue((aes128cbc_EncryptionResult.Success && aes128cbc_DecryptionResult.Success && aes128cbc_DecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }

        [TestMethod]
        public void Test_DecryptString_without_encryption_data_appended()
        {
            string errorMessage = "";
            var appendEncryptionData = false;
            var aes128cbc_DecryptionResult = new AesEncryptionResult();

            var aes128cbc_EncryptionResult = _aes128cbc.EncryptString(_testString, _password, appendEncryptionDataToOutputString: appendEncryptionData);

            if (aes128cbc_EncryptionResult.Success)
            {
                aes128cbc_DecryptionResult = _aes128cbc.DecryptString(aes128cbc_EncryptionResult.EncryptedDataBytes, Encoding.UTF8.GetBytes(_password), 
                    hasEncryptionDataAppendedInIntputString: appendEncryptionData, aes128cbc_EncryptionResult.Tag, aes128cbc_EncryptionResult.Salt, aes128cbc_EncryptionResult.IV);

                if (!aes128cbc_DecryptionResult.Success)
                    errorMessage = aes128cbc_DecryptionResult.Message;
            }
            else
                errorMessage = aes128cbc_EncryptionResult.Message;

            Assert.IsTrue((aes128cbc_EncryptionResult.Success && aes128cbc_DecryptionResult.Success && aes128cbc_DecryptionResult.DecryptedDataString.Equals(_testString)), errorMessage);
        }
    }
}
