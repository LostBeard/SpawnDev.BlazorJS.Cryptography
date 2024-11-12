using SpawnDev.BlazorJS.JSObjects;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Windows, Linux platform ECDH key
    /// </summary>
    public class PortableECDHKeyNet : PortableECDHKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public ECDiffieHellman Key { get; protected set; }
        /// <summary>
        /// The named curve
        /// </summary>
        public override string NamedCurve => $"P-{Key.KeySize}";
        /// <summary>
        /// Create a new instance
        /// </summary>
        /// <param name="key"></param>
        public PortableECDHKeyNet(ECDiffieHellman key)
        {
            Key = key;
        }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Key?.Dispose();
            }
        }
    }
}
