using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace HalfSipHash
{
    public class HalfSipHash32 : KeyedHashAlgorithm
    {
        private const int cROUNDS = 2;
        private const int fROUNDS = 4;

        private byte[] _key;

        private Queue<byte> _input = new Queue<byte>();
        private volatile int _inputLength;

        private volatile byte[] _overflow;

        private uint v0 = 0, v1 = 0;
        private uint v2 = 0x6c796765U, v3 = 0x74656462U;

        public HalfSipHash32(byte[] key)
        {
            _key = key;
            _overflow = new byte[0];
            Initialize();
        }

        public override void Initialize()
        {
            if (_key.Length < 8)
            {
                Console.WriteLine($"Invalid key length: {_key.Length}");
                throw new ArgumentOutOfRangeException();
            }

            uint k0 = BitConverter.ToUInt32(_key);
            uint k1 = BitConverter.ToUInt32(_key, 4);
            v3 ^= k1;
            v2 ^= k0;
            v1 ^= k1;
            v0 ^= k0;
        }

        private void ProcessInput()
        {
            while(_input.Count >= 4)
            {
                var buffer = new byte[4];
                for(var idx = 0; idx < 4; idx++)
                    buffer[idx] = _input.Dequeue();

                var next = BitConverter.ToUInt32(buffer);
                v3 ^= next;

                for (int idx = 0; idx < cROUNDS; ++idx)
                    Sip();

                v0 ^= next;
                _inputLength += 4;
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for(int i = 0; i < cbSize; i++)
                _input.Enqueue(array[ibStart + i]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Sip()
        {
            v0 += v1;
            v1 = (uint)(((v1) << (5)) | ((v1) >> (32 - (5))));
            v1 ^= v0;
            v0 = (uint)(((v0) << (16)) | ((v0) >> (32 - (16))));
            v2 += v3;
            v3 = (uint)(((v3) << (8)) | ((v3) >> (32 - (8))));
            v3 ^= v2;
            v0 += v3;
            v3 = (uint)(((v3) << (7)) | ((v3) >> (32 - (7))));
            v3 ^= v0;
            v2 += v1;
            v1 = (uint)(((v1) << (13)) | ((v1) >> (32 - (13))));
            v1 ^= v2;
            v2 = (uint)(((v2) << (16)) | ((v2) >> (32 - (16))));
        }

        protected override byte[] HashFinal()
        {
            ProcessInput();

            var output = new byte[4];
            var left = _input.Count;
            var length = _inputLength + left;

            int i;
            uint b = ((uint)length) << 24;
            var lim = length - left;

            var lastBlock = new byte[left];
            for(i = 0; i < left; i++)
                lastBlock[i] = _input.Dequeue();

            if(left > 2)
                b |= ((uint)lastBlock[2]) << 16;

            if(left > 1)
                b |= ((uint)lastBlock[1]) << 8;
            
            if(left > 0)
                b |= (uint)lastBlock[0];
            
            v3 ^= b;

            for (i = 0; i < cROUNDS; ++i)
                Sip();

            v0 ^= b;
            v2 ^= 0xff;

            for (i = 0; i < fROUNDS; ++i)
                Sip();

            b = v1 ^ v3;

            (output)[0] = (byte)((b));
            (output)[1] = (byte)((b) >> 8);
            (output)[2] = (byte)((b) >> 16);
            (output)[3] = (byte)((b) >> 24);

            return output;
        }
    }
}