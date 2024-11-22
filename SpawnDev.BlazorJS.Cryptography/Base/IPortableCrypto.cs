
namespace SpawnDev.BlazorJS.Cryptography
{
    public interface IPortableCrypto
    {
        Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData);
        Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey);
        Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength);
        Task<byte[]> Digest(string hashName, byte[] data);
        Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes);
        Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key);
        Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key);
        Task<byte[]> ExportPublicKeySpki(PortableECDHKey key);
        Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key);
        Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = "SHA-256", int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true);
        Task<PortableECDHKey> GenerateECDHKey(string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = "P-521", bool extractable = true);
        Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = "P-521", bool extractable = true);
        byte[] RandomBytes(int length);
        void RandomBytesFill(byte[] data);
        void RandomBytesFill(Span<byte> data);
        Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = "SHA-512");
        Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = "SHA-512");
    }
}