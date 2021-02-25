/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.HashResults;
using CryptHash.Net.Util;
using System;
using System.Linq;

namespace CryptHash.Net.Hash
{
    public class Argon2id
    {
        public Argon2idHashResult ComputeHash(byte[] stringToComputeHashBytes, int iterations, int kBmemorySize, int degreeOfParallelism, int amountBytesToReturn,
            byte[] salt = null, byte[] associatedData = null, byte[] knownSecret = null)
        {
            try
            {
                salt = salt ?? CommonMethods.GenerateSalt(); // generate a 128 bits salt, if not provided
                degreeOfParallelism = (degreeOfParallelism <= 0 ? Environment.ProcessorCount : degreeOfParallelism);

                using (var argon2id = new Konscious.Security.Cryptography.Argon2id(stringToComputeHashBytes)
                {
                    Salt = salt,
                    DegreeOfParallelism = degreeOfParallelism,
                    Iterations = iterations,
                    MemorySize = kBmemorySize,
                    AssociatedData = associatedData,
                    KnownSecret = knownSecret
                })
                {
                    var hashBytes = argon2id.GetBytes(amountBytesToReturn);

                    return new Argon2idHashResult()
                    {
                        Success = true,
                        HashBytes = hashBytes,
                        HashString = Convert.ToBase64String(hashBytes),
                        Message = MessageDictionary.Instance["Hash.ComputeSuccess"],
                        SaltBytes = salt,
                        Iterations = iterations,
                        DegreeOfParallelism = degreeOfParallelism,
                        KBMemorySize = kBmemorySize,
                        AssociatedData = associatedData,
                        KnownSecret = knownSecret
                    };
                }
            }
            catch (Exception ex)
            {
                return new Argon2idHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public Argon2idHashResult VerifyHash(byte[] hash, byte[] stringToComputeHashBytes, int iterations, int kBmemorySize, int degreeOfParallelism, int amountBytesToReturn,
            byte[] salt = null, byte[] associatedData = null, byte[] knownSecret = null)
        {
            try
            {
                var newHash = ComputeHash(stringToComputeHashBytes, iterations, kBmemorySize, degreeOfParallelism, amountBytesToReturn, salt, associatedData, knownSecret);

                return new Argon2idHashResult()
                {
                    Success = newHash.HashBytes.SequenceEqual(hash),
                    HashBytes = newHash.HashBytes,
                    HashString = newHash.HashString,
                    Message = $"{(newHash.HashBytes.SequenceEqual(hash) ? MessageDictionary.Instance["Hash.Match"] : MessageDictionary.Instance["Hash.DoesNotMatch"])}",
                    SaltBytes = salt,
                    Iterations = iterations,
                    DegreeOfParallelism = degreeOfParallelism,
                    KBMemorySize = kBmemorySize,
                    AssociatedData = associatedData,
                    KnownSecret = knownSecret
                };
            }
            catch (Exception ex)
            {
                return new Argon2idHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }
    }
}
