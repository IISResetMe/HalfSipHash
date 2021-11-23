using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Running;

namespace HalfSipHash.Tests
{
    using HalfSipHash;

    public class BenchmarkTest
    {
        public static void RunBenchmarkTests()
        {
            BenchmarkRunner.Run<HalfSipHashVsHMACSHA1Benchmark>();
        }
    }

    public class HalfSipHashVsHMACSHA1Benchmark
    {
        private class HashBag
        {
            private HashSet<byte[]> _set = new HashSet<byte[]>();
            internal void Add(byte[] value)
            {
                _set.Add(value);
            }
        }
        private static readonly byte[] _key = new byte[]{ 0x1A, 0xA0, 0x76, 0x7D, 0xC6, 0xD1, 0x47, 0x3A, 0x80, 0xE1, 0xC, 0x3A, 0xB3, 0xA1, 0x9E, 0xAE };
        private HalfSipHash32 _hsh = new HalfSipHash32(_key);
        private HMACSHA1 _hmac = new HMACSHA1(_key);

        private int N = 1024;
        private byte[] _data;

        public HalfSipHashVsHMACSHA1Benchmark()
        {
            _data = new byte[N];
            new Random().NextBytes(_data);
        }

        [Benchmark()]
        public byte[] TestHSH(){
            byte[] hash = new byte[0];
            int hashRounds = 10000;
            for(int i = 0; i < hashRounds; i++)
                hash = _hsh.ComputeHash(_data);
            
            return hash;
        }

        [Benchmark]
        public byte[] TestHMAC(){
            byte[] hash = new byte[0];
            int hashRounds = 10000;
            for(int i = 0; i < hashRounds; i++)
                hash = _hmac.ComputeHash(_data);
            
            return hash;
        }
    }
}