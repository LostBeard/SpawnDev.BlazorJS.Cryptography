
namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// PortableCrypto interface
    /// </summary>
    public interface IPortableCrypto
    {
        // Digest
        Task<byte[]> Digest(string hashName, byte[] data);
        // AES-GCM
        Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData);
        Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes);
        Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        // AES-CBC
        Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7);
        Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7);
        Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7);
        Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7);
        Task<PortableAESCBCKey> GenerateAESCBCKey(int length, bool extractable = true);
        Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true);
        Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key);
        // ECDH
        Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey);
        Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength);
        Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key);
        Task<byte[]> ExportPublicKeySpki(PortableECDHKey key);
        Task<PortableECDHKey> GenerateECDHKey(string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = "P-521", bool extractable = true);
        // ECDSA
        Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key);
        Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key);
        Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = "P-521", bool extractable = true);
        Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = "SHA-512");
        Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = "SHA-512");
        // Random
        byte[] RandomBytes(int length);
        void RandomBytesFill(byte[] data);
        void RandomBytesFill(Span<byte> data);
    }
}