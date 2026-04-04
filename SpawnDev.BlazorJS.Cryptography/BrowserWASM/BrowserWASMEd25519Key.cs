using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Cryptography.BrowserWASM
{
    /// <summary>
    /// Browser platform Ed25519 key (WASM in-process)
    /// </summary>
    public class BrowserWASMEd25519Key : PortableEd25519Key
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public CryptoKeyPair Key { get; protected set; }
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
        public BrowserWASMEd25519Key(CryptoKeyPair key)
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
