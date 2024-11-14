using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public abstract class PortableCrypto
    {
        public abstract Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData);
        public abstract Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey);
        public abstract Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength);
        public abstract Task<byte[]> Digest(string hashName, byte[] data);
        public abstract Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes);
        public abstract Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key);
        public abstract Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key);
        public abstract Task<byte[]> ExportPublicKeySpki(PortableECDHKey key);
        public abstract Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key);
        public abstract Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        public abstract Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        public abstract Task<PortableECDHKey> GenerateECDHKey(string namedCurve = "P-521", bool extractable = true);
        public abstract Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = "P-521", bool extractable = true);
        public abstract Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = "P-521", bool extractable = true);
        public abstract Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = "P-521", bool extractable = true);
        public abstract Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = "P-521", bool extractable = true);
        public abstract Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = "P-521", bool extractable = true);
        public abstract byte[] RandomBytes(int length);
        public abstract void RandomBytesFill(byte[] data);
        public abstract void RandomBytesFill(Span<byte> data);
        public abstract Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = "SHA-512");
        public abstract Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = "SHA-512");

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
        protected static HashAlgorithmName HashNameToHashAlgorithmName(string hashName)
        {
            return hashName switch
            {
                HashName.SHA512 => HashAlgorithmName.SHA512,
                HashName.SHA384 => HashAlgorithmName.SHA384,
                HashName.SHA256 => HashAlgorithmName.SHA256,
                _ => throw new NotImplementedException($"HashName not implemented {hashName}")
            };
        }
        protected static ECCurve NamedCurveToECCurve(string namedCurve)
        {
            return namedCurve switch
            {
                NamedCurve.P521 => ECCurve.NamedCurves.nistP521,
                NamedCurve.P384 => ECCurve.NamedCurves.nistP384,
                NamedCurve.P256 => ECCurve.NamedCurves.nistP256,
                _ => throw new NotImplementedException($"NamedCurve not implemented {namedCurve}")
            };
        }
        protected static int NamedCurveBitLength(string namedCurve, bool compatibilityMode = false)
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