using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Cryptography.BrowserWASM
{
    /// <summary>
    /// Browser platform ECDH key
    /// </summary>
    public class BrowserWASMECDHKey : PortableECDHKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKeyPair Key { get; protected set; }
        /// <summary>
        /// The named curve
        /// </summary>
        public override string NamedCurve
        {
            get
            {
                using var privateKey = Key.PrivateKey;
                if (privateKey != null) return privateKey.JSRef!.Get<string>("algorithm.namedCurve");
                using var publicKey = Key.PublicKey;
                if (publicKey != null) return publicKey.JSRef!.Get<string>("algorithm.namedCurve");
                return string.Empty;
            }
        }
        /// <summary>
        /// Returns true if the key can be extracted
        /// </summary>
        public override bool Extractable
        {
            get
            {
                using var privateKey = Key.PrivateKey;
                return privateKey?.Extractable ?? false;
            }
        }
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages
        {
            get
            {
                var ret = new List<string>();
                using var privateKey = Key.PrivateKey;
                if (privateKey != null) ret.AddRange(privateKey.Usages);
                using var publicKey = Key.PublicKey;
                if (publicKey != null) ret.AddRange(publicKey.Usages);
                return ret.ToArray();
            }
        }
        /// <summary>
        /// Create a new instance
        /// </summary>
        /// <param name="key"></param>
        public BrowserWASMECDHKey(CryptoKeyPair key)
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
