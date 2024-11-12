using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Windows, Linux platform ECDSA key
    /// </summary>
    public class PortableECDSAKeyNet : PortableECDSAKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public ECDsa Key { get; protected set; }
        /// <summary>
        /// The named curve
        /// </summary>
        public override string NamedCurve => $"P-{Key.KeySize}";
        /// <summary>
        /// Create a new instance
        /// </summary>
        /// <param name="key"></param>
        public PortableECDSAKeyNet(ECDsa key)
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
