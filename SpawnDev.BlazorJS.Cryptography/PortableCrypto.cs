using SpawnDev.BlazorJS.JSObjects;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Cross platform cryptography tools
    /// </summary>
    public partial class PortableCrypto
    {
        BlazorJSRuntime JS { get; set; }
        Lazy<SubtleCrypto>? _SubtleCrypto = null;
        Lazy<Crypto>? _Crypto = null;
        SubtleCrypto? SubtleCrypto => _SubtleCrypto?.Value;
        Crypto? Crypto => _Crypto?.Value;
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="js"></param>
        [SupportedOSPlatform("browser")]
        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("windows")]
        public PortableCrypto(BlazorJSRuntime js)
        {
            JS = js;
            if (OperatingSystem.IsBrowser())
            {
                _Crypto = new Lazy<Crypto>(() => JS.Get<Crypto>("crypto"));
                _SubtleCrypto = new Lazy<SubtleCrypto>(() => JS.Get<SubtleCrypto>("crypto?.subtle"));
            }
        }
        /// <summary>
        /// EC named curves
        /// </summary>
        public static class Algorithm
        {
            /// <summary>
            /// ECDSA
            /// </summary>
            public const string ECDSA = "ECDSA";
            /// <summary>
            /// P-384
            /// </summary>
            public const string ECDH = "ECDH";
            /// <summary>
            /// P-256
            /// </summary>
            public const string AESGCM = "AES-GCM";
        }
        /// <summary>
        /// EC named curves
        /// </summary>
        public static class NamedCurve
        {
            /// <summary>
            /// P-521
            /// </summary>
            public const string P521 = "P-521";
            /// <summary>
            /// P-384
            /// </summary>
            public const string P384 = "P-384";
            /// <summary>
            /// P-256
            /// </summary>
            public const string P256 = "P-256";
        }
        /// <summary>
        /// Hash names
        /// </summary>
        public static class HashName
        {
            /// <summary>
            /// SHA-1 is deprecated. Do not use in cryptographic applications.
            /// </summary>
            public const string SHA1 = "SHA-1";
            /// <summary>
            /// SHA-256
            /// </summary>
            public const string SHA256 = "SHA-256";
            /// <summary>
            /// SHA-384
            /// </summary>
            public const string SHA384 = "SHA-384";
            /// <summary>
            /// SHA-512
            /// </summary>
            public const string SHA512 = "SHA-512";
        }
        static HashAlgorithmName HashNameToHashAlgorithmName(string hashName)
        {
            return hashName switch
            {
                HashName.SHA512 => HashAlgorithmName.SHA512,
                HashName.SHA384 => HashAlgorithmName.SHA384,
                HashName.SHA256 => HashAlgorithmName.SHA256,
                _ => throw new NotImplementedException($"HashName not implemented {hashName}")
            };
        }
        static ECCurve NamedCurveToECCurve(string namedCurve)
        {
            return namedCurve switch
            {
                NamedCurve.P521 => ECCurve.NamedCurves.nistP521,
                NamedCurve.P384 => ECCurve.NamedCurves.nistP384,
                NamedCurve.P256 => ECCurve.NamedCurves.nistP256,
                _ => throw new NotImplementedException($"NamedCurve not implemented {namedCurve}")
            };
        }
        static int NamedCurveBitLength(string namedCurve, bool compatibilityMode = false)
        {
            return namedCurve switch
            {
                NamedCurve.P521 => compatibilityMode ? 512 : 521,
                NamedCurve.P384 => 384,
                NamedCurve.P256 => 256,
                _ => throw new NotImplementedException()
            };
        }
    }
}
