using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Cryptography.BrowserWASM
{
    /// <summary>
    /// Browser platform AES-CBC key
    /// </summary>
    public class BrowserWASMAESCBCKey : PortableAESCBCKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKey Key { get; protected set; }
        /// <summary>
        /// Returns true if the private key can be extracted
        /// </summary>
        public override bool Extractable => Key?.Extractable ?? false;
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages => Key?.Usages ?? System.Array.Empty<string>();
        /// <summary>
        /// Create a new instance
        /// </summary>
        public BrowserWASMAESCBCKey(CryptoKey key)
        {
            Key = key;
            var algorithmParams = key.AlgorithmAs<AesKeyGenParams>();
            KeySize = algorithmParams.Length;
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
