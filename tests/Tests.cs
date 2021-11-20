using System.Diagnostics;
using HalfSipHash;
using System.Text;
using System.Security.Cryptography;

namespace tests
{
    public static class Tests
    {

        /*
         * Test cases lifted directly from HalfSipHash C reference implementation @ https://github.com/veorq/SipHash/blob/master/halfsiphash.c
         */
        internal static readonly byte[][] c_vectors = new byte[][]
        {
            new byte[]{
                0xa9,
                0x35,
                0x9f,
                0x5b,
            },
            new byte[]{
                0x27,
                0x47,
                0x5a,
                0xb8,
            },
            new byte[]{
                0xfa,
                0x62,
                0xa6,
                0x03,
            },
            new byte[]{
                0x8a,
                0xfe,
                0xe7,
                0x04,
            },
            new byte[]{
                0x2a,
                0x6e,
                0x46,
                0x89,
            },
            new byte[]{
                0xc5,
                0xfa,
                0xb6,
                0x69,
            },
            new byte[]{
                0x58,
                0x63,
                0xfc,
                0x23,
            },
            new byte[]{
                0x8b,
                0xcf,
                0x63,
                0xc5,
            },
            new byte[]{
                0xd0,
                0xb8,
                0x84,
                0x8f,
            },
            new byte[]{
                0xf8,
                0x06,
                0xe7,
                0x79,
            },
            new byte[]{
                0x94,
                0xb0,
                0x79,
                0x34,
            },
            new byte[]{
                0x08,
                0x08,
                0x30,
                0x50,
            },
            new byte[]{
                0x57,
                0xf0,
                0x87,
                0x2f,
            },
            new byte[]{
                0x77,
                0xe6,
                0x63,
                0xff,
            },
            new byte[]{
                0xd6,
                0xff,
                0xf8,
                0x7c,
            },
            new byte[]{
                0x74,
                0xfe,
                0x2b,
                0x97,
            },
            new byte[]{
                0xd9,
                0xb5,
                0xac,
                0x84,
            },
            new byte[]{
                0xc4,
                0x74,
                0x64,
                0x5b,
            },
            new byte[]{
                0x46,
                0x5b,
                0x8d,
                0x9b,
            },
            new byte[]{
                0x7b,
                0xef,
                0xe3,
                0x87,
            },
            new byte[]{
                0xe3,
                0x4d,
                0x10,
                0x45,
            },
            new byte[]{
                0x61,
                0x3f,
                0x62,
                0xb3,
            },
            new byte[]{
                0x70,
                0xf3,
                0x67,
                0xfe,
            },
            new byte[]{
                0xe6,
                0xad,
                0xb8,
                0xbd,
            },
            new byte[]{
                0x27,
                0x40,
                0x0c,
                0x63,
            },
            new byte[]{
                0x26,
                0x78,
                0x78,
                0x75,
            },
            new byte[]{
                0x4f,
                0x56,
                0x7b,
                0x5f,
            },
            new byte[]{
                0x3a,
                0xb0,
                0xe6,
                0x69,
            },
            new byte[]{
                0xb0,
                0x64,
                0x40,
                0x00,
            },
            new byte[]{
                0xff,
                0x67,
                0x0f,
                0xb4,
            },
            new byte[]{
                0x50,
                0x9e,
                0x33,
                0x8b,
            },
            new byte[]{
                0x5d,
                0x58,
                0x9f,
                0x1a,
            },
            new byte[]{
                0xfe,
                0xe7,
                0x21,
                0x12,
            },
            new byte[]{
                0x33,
                0x75,
                0x32,
                0x59,
            },
            new byte[]{
                0x6a,
                0x43,
                0x4f,
                0x8c,
            },
            new byte[]{
                0xfe,
                0x28,
                0xb7,
                0x29,
            },
            new byte[]{
                0xe7,
                0x5c,
                0xc6,
                0xec,
            },
            new byte[]{
                0x69,
                0x7e,
                0x8d,
                0x54,
            },
            new byte[]{
                0x63,
                0x68,
                0x8b,
                0x0f,
            },
            new byte[]{
                0x65,
                0x0b,
                0x62,
                0xb4,
            },
            new byte[]{
                0xb6,
                0xbc,
                0x18,
                0x40,
            },
            new byte[]{
                0x5d,
                0x07,
                0x45,
                0x05,
            },
            new byte[]{
                0x24,
                0x42,
                0xfd,
                0x2e,
            },
            new byte[]{
                0x7b,
                0xb7,
                0x86,
                0x3a,
            },
            new byte[]{
                0x77,
                0x05,
                0xd5,
                0x48,
            },
            new byte[]{
                0xd7,
                0x52,
                0x08,
                0xb1,
            },
            new byte[]{
                0xb6,
                0xd4,
                0x99,
                0xc8,
            },
            new byte[]{
                0x08,
                0x92,
                0x20,
                0x2e,
            },
            new byte[]{
                0x69,
                0xe1,
                0x2c,
                0xe3,
            },
            new byte[]{
                0x8d,
                0xb5,
                0x80,
                0xe5,
            },
            new byte[]{
                0x36,
                0x97,
                0x64,
                0xc6,
            },
            new byte[]{
                0x01,
                0x6e,
                0x02,
                0x04,
            },
            new byte[]{
                0x3b,
                0x85,
                0xf3,
                0xd4,
            },
            new byte[]{
                0xfe,
                0xdb,
                0x66,
                0xbe,
            },
            new byte[]{
                0x1e,
                0x69,
                0x2a,
                0x3a,
            },
            new byte[]{
                0xc6,
                0x89,
                0x84,
                0xc0,
            },
            new byte[]{
                0xa5,
                0xc5,
                0xb9,
                0x40,
            },
            new byte[]{
                0x9b,
                0xe9,
                0xe8,
                0x8c,
            },
            new byte[]{
                0x7d,
                0xbc,
                0x81,
                0x40,
            },
            new byte[]{
                0x7c,
                0x07,
                0x8e,
                0xc5,
            },
            new byte[]{
                0xd4,
                0xe7,
                0x6c,
                0x73,
            },
            new byte[]{
                0x42,
                0x8f,
                0xcb,
                0xb9,
            },
            new byte[]{
                0xbd,
                0x83,
                0x99,
                0x7a,
            },
            new byte[]{
                0x59,
                0xea,
                0x4a,
                0x74,
            },
        };

        private static readonly Random s_rng = new Random();

        private static readonly string[] terms = new[]{ new string('a', 12), new string('b', 23), new string('c', 34), new string('d', 45), new string('e', 56), new string('f', 67) };

        private static readonly Dictionary<int, byte[][]> s_testData = new Dictionary<int, byte[][]>();

        private static byte[][] GetTestData(int count)
        {
            if(!s_testData.ContainsKey(count))
                s_testData.Add(count, Enumerable.Range(0, count).Select(i => Encoding.Unicode.GetBytes(terms[s_rng.Next(0,terms.Length)])).ToArray());
            
            return s_testData[count];
        }
        
        public static void TestPerformanceHashAlgorithm(int tests = 1000)
        {
            Console.WriteLine($"Testing HashAlgorithm {tests} times");
            var testData = GetTestData(tests);
            var key = new byte[8];
            s_rng.NextBytes(key);
            var algo = new HalfSipHash32(key);
            Stopwatch sw = Stopwatch.StartNew();
            for(int i = 0; i < tests; i++)
            {
                var hash = algo.ComputeHash(testData[i]);
            }
            sw.Stop();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"  Ran test in {sw.Elapsed}");
            Console.ResetColor();
        }

        public static void TestCaseHashAlgorithm()
        {
            Console.Write(
@"

#####################
# HalfSipHash32     #
#####################

"
            );
            var k = new byte[16];
            var _in = new byte[64];
            for(byte i = 0; i < 16; i++)
                k[i] = i;
            
            for (byte i = 0; i < 64; i++)
            {
                _in[i] = i;
                var sipHash = new HalfSipHash32(k);
                var hash = sipHash.ComputeHash(_in, 0, i);

                var expect = BitConverter.ToString(c_vectors[i]).Replace("-","");
                var actual = BitConverter.ToString(hash).Replace("-","");
                var equals = expect.Equals(actual);
                Console.WriteLine();
                if(!equals)
                    Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Expected: " + expect);
                Console.WriteLine("Got     : " + actual);
                Console.ResetColor();
                if(!equals)
                    throw new TestFailedException();
            }
        }

        [System.Serializable]
        public class TestFailedException : System.Exception
        {
            public TestFailedException() { }
            public TestFailedException(string message) : base(message) { }
            public TestFailedException(string message, System.Exception inner) : base(message, inner) { }
            protected TestFailedException(
                System.Runtime.Serialization.SerializationInfo info,
                System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
        }
    }
}