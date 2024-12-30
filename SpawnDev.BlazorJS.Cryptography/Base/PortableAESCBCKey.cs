namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// AES-CBC key abstract class
    /// </summary>
    public abstract class PortableAESCBCKey : PortableKey
    {
        /// <summary>
        /// Key algorithm
        /// </summary>
        public override string AlgorithmName { get; } = "AES-CBC";
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages { get; protected set; } = new string[] { "encrypt", "decrypt" };
        /// <summary>
        /// The key size
        /// </summary>
        public virtual int KeySize { get; protected set; }
    }
}
