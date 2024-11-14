namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// AES-GCM key abstract class
    /// </summary>
    public abstract class PortableAESGCMKey : PortableKey
    {
        /// <summary>
        /// Key algorithm
        /// </summary>
        public override string AlgorithmName { get; } = "AES-GCM";
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages { get; protected set; } = new string[] { "encrypt", "decrypt" };
        /// <summary>
        /// Tag size used for encryption and decryption
        /// </summary>
        public virtual int TagSizeBytes { get; protected set; }
        /// <summary>
        /// Nonce size used for encryption and decryption
        /// </summary>
        public virtual int NonceSizeBytes { get; protected set; }
    }
}
