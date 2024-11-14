using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography.Browser
{
    /// <summary>
    /// Browser platform AES-GCM key
    /// </summary>
    public class BrowserAESGCMKey : PortableAESGCMKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKeyAsync Key { get; protected set; }
        /// <summary>
        /// Create a new instance
        /// </summary>
        public BrowserAESGCMKey(CryptoKeyAsync key, int nonceSizeBytes, int tagSizeBytes, bool extractable, string[] usages)
        {
            Key = key;
            NonceSizeBytes = nonceSizeBytes;
            TagSizeBytes = tagSizeBytes;
            Extractable = extractable;
            Usages = usages;
        }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        public override async ValueTask DisposeAsync()
        {
            if (Key != null) await Key.DisposeAsync();
        }
    }
}
