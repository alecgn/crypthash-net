using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptHash.Net.Tests.Encoding
{
    [TestClass]
    public class Hexadecimal_Tests
    {
        [TestMethod]
        public void Managed_and_unmanaged_generated_hex_matches()
        {
            var randomBytes = CryptHash.Net.Util.CommonMethods.GenerateRandomBytes(32);

            var managedGeneratedHex = CryptHash.Net.Encoding.Hexadecimal.ToHexString(randomBytes);
            var unmanagedGeneratedHex = CryptHash.Net.Encoding.HighPerformanceHexadecimal.ToHexString(randomBytes);

            Assert.AreEqual(managedGeneratedHex, unmanagedGeneratedHex);
        }
    }
}
