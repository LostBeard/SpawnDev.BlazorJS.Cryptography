using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography.Browser
{
    /// <summary>
    /// Browser platform ECDSA key
    /// </summary>
    public class BrowserECDSAKey : PortableECDSAKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKeyPairAsync Key { get; protected set; }
        /// <summary>
        /// Create a new instance
        /// </summary>
        public BrowserECDSAKey(CryptoKeyPairAsync key, string namedCurve, bool extractable, string[] usages)
        {
            Key = key;
            NamedCurve = namedCurve;
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
