using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// PortableCrypto base class shared by all implementations
    /// </summary>
    public abstract partial class PortableCrypto : IPortableCrypto
    {
        // Digest
        /// <summary>
        /// Hash data using the specified hash algorithm
        /// </summary>
        /// <param name="hashName"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Digest(string hashName, byte[] data);
        // AES-GCM
        /// <summary>
        /// Decrypt data using an AES-GCM key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData);
        /// <summary>
        /// Decrypt data using an AES-GCM key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes);
        /// <summary>
        /// Generate an AES-GCM key
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="iterations"></param>
        /// <param name="hashName"></param>
        /// <param name="keySizeBytes"></param>
        /// <param name="tagSizeBytes"></param>
        /// <param name="nonceSizeBytes"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        /// <summary>
        /// Generate an AES-GCM key
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="salt"></param>
        /// <param name="iterations"></param>
        /// <param name="hashName"></param>
        /// <param name="keySizeBytes"></param>
        /// <param name="tagSizeBytes"></param>
        /// <param name="nonceSizeBytes"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        // AES-CBC
        /// <summary>
        /// Decrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Decrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <param name="iv"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <param name="iv"></param>
        /// <param name="prependIV"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <param name="prependIV"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Generate an AES-CBC key
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableAESCBCKey> GenerateAESCBCKey(int keySize, bool extractable = true);
        /// <summary>
        /// Import an AES-CBC key
        /// </summary>
        /// <param name="rawKey"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true);
        /// <summary>
        /// Export an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public abstract Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key);
        // ECDH
        /// <summary>
        /// Derive bits from an ECDH key
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <returns></returns>
        public abstract Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey);
        /// <summary>
        /// Derive bits from an ECDH key
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <param name="bitLength"></param>
        /// <returns></returns>
        public abstract Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength);
        /// <summary>
        /// Export an ECDH private key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public abstract Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key);
        /// <summary>
        /// Export an ECDH public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public abstract Task<byte[]> ExportPublicKeySpki(PortableECDHKey key);
        /// <summary>
        /// Generate an ECDH key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableECDHKey> GenerateECDHKey(string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDH key
        /// </summary>
        /// <param name="publicKeySpki"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDH key
        /// </summary>
        /// <param name="publicKeySpki"></param>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = "P-521", bool extractable = true);
        // ECDSA
        /// <summary>
        /// Export an ECDSA private key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public abstract Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key);
        /// <summary>
        /// Export an ECDSA public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public abstract Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key);
        /// <summary>
        /// Generate an ECDSA key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDSA key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDSA key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="privateKeyPkcs8Data"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public abstract Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Sign a message
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        public abstract Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = "SHA-512");
        /// <summary>
        /// Verify a signature
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        public abstract Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = "SHA-512");
        // Random
        /// <summary>
        /// Generate a random byte array
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public abstract byte[] RandomBytes(int length);
        /// <summary>
        /// Fill a byte array with random bytes
        /// </summary>
        /// <param name="data"></param>
        public abstract void RandomBytesFill(byte[] data);
        /// <summary>
        /// Fill a Span with random bytes
        /// </summary>
        /// <param name="data"></param>
        public abstract void RandomBytesFill(Span<byte> data);

        /// <summary>
        /// AES-CBC block size
        /// </summary>
        public const int AES_CBC_BLOCK_SIZE = 16;

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
            /// ECDH
            /// </summary>
            public const string ECDH = "ECDH";
            /// <summary>
            /// AES-GCM
            /// </summary>
            public const string AESGCM = "AES-GCM";
            /// <summary>
            /// AES-CBC
            /// </summary>
            public const string AESCBC = "AES-CBC";
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
        /// <summary>
        /// Hash name to HashAlgorithmName
        /// </summary>
        /// <param name="hashName"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
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
        /// <summary>
        /// Named curve to ECCurve
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
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
        /// <summary>
        /// Named curve bit length
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="compatibilityMode"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
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