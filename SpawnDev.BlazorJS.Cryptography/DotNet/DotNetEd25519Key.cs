
namespace SpawnDev.BlazorJS.Cryptography.DotNet
{
    /// <summary>
    /// DotNet platform Ed25519 key. Wraps a 32-byte seed and 32-byte public key.
    /// Uses Ed25519Managed (pure C# RFC 8032 implementation).
    /// </summary>
    public class DotNetEd25519Key : PortableEd25519Key
    {
        /// <summary>32-byte private key seed (null if public-only)</summary>
        internal byte[]? Seed { get; }
        /// <summary>32-byte public key</summary>
        internal byte[] PublicKeyBytes { get; }
        /// <summary>
        /// Create a key pair (seed + public key)
        /// </summary>
        public DotNetEd25519Key(byte[] seed, byte[] publicKey)
        {
            Seed = seed;
            PublicKeyBytes = publicKey;
        }
        /// <summary>
        /// Create a public-only key
        /// </summary>
        public DotNetEd25519Key(byte[] publicKey)
        {
            PublicKeyBytes = publicKey;
        }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing && Seed != null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(Seed);
        }
    }
}
