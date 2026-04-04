using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography.Browser
{
    /// <summary>
    /// Browser platform Ed25519 key
    /// </summary>
    public class BrowserEd25519Key : PortableEd25519Key
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKeyPairAsync Key { get; protected set; }
        /// <summary>
        /// Create a new instance
        /// </summary>
        public BrowserEd25519Key(CryptoKeyPairAsync key, bool extractable, string[] usages)
        {
            Key = key;
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
