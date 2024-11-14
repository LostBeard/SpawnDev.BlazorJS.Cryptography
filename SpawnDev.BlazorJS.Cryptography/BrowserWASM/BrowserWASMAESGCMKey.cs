using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Cryptography.BrowserWASM
{
    /// <summary>
    /// Browser platform AES-GCM key
    /// </summary>
    public class BrowserWASMAESGCMKey : PortableAESGCMKey
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
        /// <param name="key"></param>
        /// <param name="nonceSizeBytes"></param>
        /// <param name="tagSizeBytes"></param>
        public BrowserWASMAESGCMKey(CryptoKey key, int nonceSizeBytes, int tagSizeBytes)
        {
            Key = key;
            NonceSizeBytes = nonceSizeBytes;
            TagSizeBytes = tagSizeBytes;
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
