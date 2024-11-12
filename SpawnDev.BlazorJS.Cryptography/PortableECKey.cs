namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Elliptic curve key abstract class
    /// </summary>
    public abstract class PortableECKey : PortableKey
    {
        /// <summary>
        /// The named curve
        /// </summary>
        public abstract string NamedCurve { get; }
    }
}
