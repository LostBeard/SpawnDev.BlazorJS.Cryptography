using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography.Browser
{
    /// <summary>
    /// Browser platform AES-CBC key
    /// </summary>
    public class BrowserAESCBCKey : PortableAESCBCKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKeyAsync Key { get; protected set; }
        /// <summary>
        /// Create a new instance
        /// </summary>
        public BrowserAESCBCKey(CryptoKeyAsync key, int keySize, bool extractable)
        {
            Key = key;
            KeySize = keySize;
            Extractable = extractable;
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
