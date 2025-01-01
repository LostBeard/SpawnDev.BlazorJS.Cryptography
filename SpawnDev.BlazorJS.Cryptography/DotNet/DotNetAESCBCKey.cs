using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography.DotNet
{
    /// <summary>
    /// Windows, Linux platform AES-CBC key
    /// </summary>
    public class DotNetAESCBCKey : PortableAESCBCKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public Aes Key { get; protected set; }
        /// <summary>
        /// The key size
        /// </summary>
        public override int KeySize => Key?.KeySize ?? 0;
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="key"></param>
        public DotNetAESCBCKey(Aes key)
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
