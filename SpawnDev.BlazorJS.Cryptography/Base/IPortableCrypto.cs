
namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// PortableCrypto interface
    /// </summary>
    public interface IPortableCrypto
    {
        // Digest
        /// <summary>
        /// Hash data using the specified hash algorithm
        /// </summary>
        /// <param name="hashName"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        Task<byte[]> Digest(string hashName, byte[] data);
        // AES-GCM
        /// <summary>
        /// Decrypt data using the specified key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData);
        /// <summary>
        /// Encrypt data using the specified key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <returns></returns>
        Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes);
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
        Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
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
        Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        // AES-CBC
        /// <summary>
        /// Decrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Decrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <param name="iv"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <param name="iv"></param>
        /// <param name="prependIV"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <param name="prependIV"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7);
        /// <summary>
        /// Generate an AES-CBC key
        /// </summary>
        /// <param name="length"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableAESCBCKey> GenerateAESCBCKey(int length, bool extractable = true);
        /// <summary>
        /// Import an AES-CBC key
        /// </summary>
        /// <param name="rawKey"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true);
        /// <summary>
        /// Export an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key);
        // ECDH
        /// <summary>
        /// Derive bits from an ECDH key
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <returns></returns>
        Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey);
        /// <summary>
        /// Derive bits from an ECDH key
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <param name="bitLength"></param>
        /// <returns></returns>
        Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength);
        /// <summary>
        /// Export an ECDH private key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key);
        /// <summary>
        /// Export an ECDH public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> ExportPublicKeySpki(PortableECDHKey key);
        /// <summary>
        /// Generate an ECDH key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableECDHKey> GenerateECDHKey(string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDH key
        /// </summary>
        /// <param name="publicKeySpki"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDH key
        /// </summary>
        /// <param name="publicKeySpki"></param>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = "P-521", bool extractable = true);
        // ECDSA
        /// <summary>
        /// Export an ECDSA private key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key);
        /// <summary>
        /// Export an ECDSA public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key);
        /// <summary>
        /// Generate an ECDSA key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDSA key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Import an ECDSA key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="privateKeyPkcs8Data"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = "P-521", bool extractable = true);
        /// <summary>
        /// Sign data
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = "SHA-512");
        /// <summary>
        /// Verify a signature
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = "SHA-512");
        // Random
        /// <summary>
        /// Generate random bytes
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        byte[] RandomBytes(int length);
        /// <summary>
        /// Fill a byte array with random bytes
        /// </summary>
        /// <param name="data"></param>
        void RandomBytesFill(byte[] data);
        /// <summary>
        /// Fill a Span with random bytes
        /// </summary>
        /// <param name="data"></param>
        void RandomBytesFill(Span<byte> data);
    }
}