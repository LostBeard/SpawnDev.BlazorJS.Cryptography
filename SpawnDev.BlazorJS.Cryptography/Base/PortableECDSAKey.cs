namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// ECDSA abstract class
    /// </summary>
    public abstract class PortableECDSAKey : PortableECKey
    {
        /// <summary>
        /// Key algorithm
        /// </summary>
        public override string AlgorithmName { get; } = "ECDSA";
        /// <summary>
        /// Key usages
        /// </summary>
        public override string[] Usages { get; protected set; } = new string[] { "sign", "verify" };
    }
}
