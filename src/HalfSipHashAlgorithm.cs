using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace HalfSipHash
{
    public class HalfSipHash32 : KeyedHashAlgorithm
    {
        public struct State
        {
            private const int cROUNDS = 2;
            private const int fROUNDS = 4;

            private Queue<byte> _input = new Queue<byte>();
            private volatile int _inputLength;

            private volatile byte[] _overflow;
            private int _oid = 0;

            private uint v0, v1, v2, v3;

            public State(uint k0, uint k1)
            {
                v3 = 0x74656462U ^ k1;
                v2 = 0x6c796765U ^ k0;
                v1 = 0 ^ k1;
                v0 = 0 ^ k0;

                _inputLength = 0;
                _overflow = new byte[4];
            }

            internal void Add(byte b)
            {
                _overflow[_oid++] = b;
                _oid %= 4;
                if(_oid == 0)
                {
                    ProcessInput(BitConverter.ToUInt32(_overflow));
                }
            }

            internal void Process(byte[] array, int offset, int length)
            {
                for(int i = 0; i < length; i++)
                {
                    _overflow[_oid++] = array[i + offset];
                    _oid %= 4;
                    if(_oid == 0)
                    {
                        ProcessInput(BitConverter.ToUInt32(_overflow));
                    }
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal void ProcessInput(uint input)
            {
                v3 ^= input;

                for (int idx = 0; idx < cROUNDS; ++idx)
                    Sip();

                v0 ^= input;

                _inputLength += sizeof(uint);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal uint Finalize()
            {
                var length = _inputLength + _oid;

                uint b = ((uint)length) << 24;

                if(_oid > 2)
                    b |= ((uint)_overflow[2]) << 16;

                if(_oid > 1)
                    b |= ((uint)_overflow[1]) << 8;
                
                if(_oid > 0)
                    b |= (uint)_overflow[0];
                
                v3 ^= b;

                for (int i = 0; i < cROUNDS; ++i)
                    Sip();

                v0 ^= b;
                v2 ^= 0xff;

                for (int i = 0; i < fROUNDS; ++i)
                    Sip();

                return v1 ^ v3;
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
        }

        private State _state;

        public HalfSipHash32(byte[] key)
        {
            if (key.Length < 8)
            {
                throw new ArgumentOutOfRangeException(nameof(key), $"Invalid key length: {key.Length}");
            }

            Key = key;
            Initialize();
        }

        public override void Initialize()
        {
            _state = new State(BitConverter.ToUInt32(Key), 
                               BitConverter.ToUInt32(Key, 4));
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _state.Process(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            var b = _state.Finalize();

            return new []{
                (byte)(b),
                (byte)(b >> 8),
                (byte)(b >> 16),
                (byte)(b >> 24)
            };
        }
    }
}