namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserCrypto
    {
        /// <summary>
        /// Hash the specified data using the specified hash algorithm
        /// </summary>
        /// <param name="hashName"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> Digest(string hashName, byte[] data)
        {
            await using var arrayBuffer = await SubtleCrypto.Digest(hashName, data);
            var hash = await arrayBuffer.ReadBytes();
            return hash;
        }
    }
}
