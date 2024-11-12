using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class PortableCrypto
    {
        /// <summary>
        /// Returns a bye array with the specified number of random bytes
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public byte[] RandomBytes(int length)
        {
            return RandomNumberGenerator.GetBytes(length);
        }
        /// <summary>
        /// Fill the byte array with random data
        /// </summary>
        /// <param name="data"></param>
        public void RandomBytesFill(byte[] data)
        {
            RandomNumberGenerator.Fill(data);
        }
        /// <summary>
        /// Fill the byte span with random data
        /// </summary>
        /// <param name="data"></param>
        public void RandomBytesFill(Span<byte> data)
        {
            RandomNumberGenerator.Fill(data);
        }
    }
}
