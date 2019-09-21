using CryptHash.Net.Encryption.Utils;
using System;
using System.Linq;

namespace CryptHash.Net.KDF
{
    public class Argon2id
    {
        public byte[] HashPassword(int amountBytesToReturn, byte[] passwordBytes, int iterations, int memorySize, byte[] salt = null, 
            byte[] associatedData = null, byte[] knownSecret = null, int degreeOfParallelism = 0)
        {
            salt = salt ?? EncryptionUtils.GenerateRandomBytes(16); // generate a 128 bits salt, if not provided
            degreeOfParallelism = (degreeOfParallelism == 0 ? Environment.ProcessorCount : degreeOfParallelism);

            var argon2id = new Konscious.Security.Cryptography.Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = degreeOfParallelism,
                Iterations = iterations,
                MemorySize = memorySize,
                AssociatedData = associatedData,
                KnownSecret = knownSecret
            };

            return argon2id.GetBytes(amountBytesToReturn);
        }

        public bool VerifyHash(byte[] hash, int amountBytesToReturn, byte[] passwordBytes, int iterations, int memorySize, byte[] salt = null,
            byte[] associatedData = null, byte[] knownSecret = null, int degreeOfParallelism = 0)
        {
            var newHash = HashPassword(amountBytesToReturn, passwordBytes, iterations, memorySize, salt, associatedData, knownSecret, degreeOfParallelism);

            return hash.SequenceEqual(newHash);
        }
    }
}
