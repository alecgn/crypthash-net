/*
 *      Alessandro Cagliostro, 2020
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

        public static HMACOutputLengthDictionary Instance { get { return _lazyHMACOutputLengthDictionary.Value; } }

        private HMACOutputLengthDictionary() { }

        private int GetOutputLength(HMACAlgorithm key)
        {
            int outputBytesLength;

            if (!_dicHMACAlgorithmOutputLengths.TryGetValue(key, out outputBytesLength))
                outputBytesLength = 0;

            return outputBytesLength;
        }

        public int this[HMACAlgorithm key]
        {
            get { return GetOutputLength(key); }
        }
    }
}
