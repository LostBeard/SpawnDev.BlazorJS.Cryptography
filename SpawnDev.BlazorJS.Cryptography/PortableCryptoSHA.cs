using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class PortableCrypto
    {
        /// <summary>
        /// Hash the specified data using the specified hash algorithm
        /// </summary>
        /// <param name="hashName"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> Digest(string hashName, byte[] data)
        {
            if (OperatingSystem.IsBrowser())
            {
                using var arrayBuffer = await SubtleCrypto!.Digest(hashName, data);
                return arrayBuffer.ReadBytes();
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
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
            }
            throw new NotImplementedException();
        }
    }
}
