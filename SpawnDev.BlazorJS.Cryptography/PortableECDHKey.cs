namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// ECDH key abstract class
    /// </summary>
    public abstract class PortableECDHKey : PortableECKey
    {
        /// <summary>
        /// Key algorithm
        /// </summary>
        public override string AlgorithmName { get; } = "ECDH";
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages { get; protected set; } = new string[] { "deriveBits", "deriveKey" };
    }
}
