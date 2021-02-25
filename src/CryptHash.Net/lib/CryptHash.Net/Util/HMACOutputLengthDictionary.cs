/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

using CryptHash.Net.Hash.Enums;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CryptHash.Net.Util
{
    public sealed class HMACOutputLengthDictionary
    {
        private static readonly Lazy<HMACOutputLengthDictionary> _lazyHMACOutputLengthDictionary = new Lazy<HMACOutputLengthDictionary>(() => new HMACOutputLengthDictionary());

        private readonly IDictionary<HMACAlgorithm, int> _dicHMACAlgorithmOutputLengths = new ConcurrentDictionary<HMACAlgorithm, int>()
        {
            [HMACAlgorithm.HMACMD5] = 128,
            [HMACAlgorithm.HMACSHA1] = 160,
            [HMACAlgorithm.HMACSHA256] = 256,
            [HMACAlgorithm.HMACSHA384] = 384,
            [HMACAlgorithm.HMACSHA512] = 512
        };

        public static HMACOutputLengthDictionary Instance => _lazyHMACOutputLengthDictionary.Value;

        private HMACOutputLengthDictionary() { }

        private int GetOutputLength(HMACAlgorithm key)
        {

            if (!_dicHMACAlgorithmOutputLengths.TryGetValue(key, out var outputBytesLength))
            {
                outputBytesLength = 0;
            }

            return outputBytesLength;
        }

        public int this[HMACAlgorithm key] => GetOutputLength(key);
    }
}
