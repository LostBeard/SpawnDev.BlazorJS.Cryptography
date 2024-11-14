using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
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
            switch (hashName)
            {
                case HashName.SHA256:
                    {
                        using var sha = SHA256.Create();
                        return sha.ComputeHash(data);
                    }
                case HashName.SHA384:
                    {
                        using var sha = SHA384.Create();
                        return sha.ComputeHash(data);
                    }
                case HashName.SHA512:
                    {
                        using var sha = SHA512.Create();
                        return sha.ComputeHash(data);
                    }
                case HashName.SHA1:
                    {
                        using var sha = SHA1.Create();
                        return sha.ComputeHash(data);
                    }
            }
            throw new NotImplementedException($"Digest failed: {hashName} hash algorithm not supported");
        }
    }
}
