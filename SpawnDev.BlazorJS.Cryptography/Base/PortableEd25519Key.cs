namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Ed25519 abstract key class.
    /// Ed25519 is EdDSA (Edwards-curve Digital Signature Algorithm) — NOT ECDSA.
    /// Fixed curve (Curve25519), fixed hash (SHA-512), 32-byte public keys, 64-byte signatures.
    /// </summary>
    public abstract class PortableEd25519Key : PortableKey
    {
        /// <summary>
        /// Key algorithm
        /// </summary>
        public override string AlgorithmName { get; } = "Ed25519";
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages { get; protected set; } = new string[] { "sign", "verify" };
    }
}
