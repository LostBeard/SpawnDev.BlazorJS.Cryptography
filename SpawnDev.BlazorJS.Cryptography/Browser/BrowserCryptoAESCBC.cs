using SpawnDev.BlazorJS.Cryptography.Browser;
using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserCrypto
    {
        /// <summary>
        /// Generate an AES-CBC key
        /// </summary>
        public override async Task<PortableAESCBCKey> GenerateAESCBCKey(int keySize, bool extractable = true)
        {
            var key = await SubtleCrypto.GenerateKey<CryptoKeyAsync>(new AesKeyGenParams { Name = Algorithm.AESCBC, Length = keySize }, extractable, new string[] { "encrypt", "decrypt" });
            return new BrowserAESCBCKey(key, keySize, extractable);
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public override async Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            await using var ret = await SubtleCrypto.Encrypt(new AesCbcParams { Iv = iv }, jsKey!.Key, plainBytes);
            var encryptedData = await ret.ReadBytes();
            if (!prependIV) return encryptedData;
            var encryptedDataLength = encryptedData.Length + iv.Length;
            var result = new byte[encryptedDataLength];
            // + iv
            iv.CopyTo(result, 0);
            // + encrypted data
            encryptedData.CopyTo(result, iv.Length);
            return result;
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            var iv = RandomBytes(16);
            return Encrypt(key, plainBytes, iv, prependIV);
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be supplied separately from the encrypted data
        /// </summary>
        public override async Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            await using var arrayBuffer = await SubtleCrypto.Decrypt(new AesCbcParams { Iv = iv }, jsKey!.Key, encryptedData);
            return await arrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be prepended to the encrypted data
        /// </summary>
        public override Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData)
        {
            var iv = new byte[16];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
            var encrypted = new byte[encryptedData.Length - 16];
            Buffer.BlockCopy(encryptedData, 16, encrypted, 0, encrypted.Length);
            return Decrypt(key, encrypted, iv);
        }
        /// <summary>
        /// Import an AES-CBC key
        /// </summary>
        /// <param name="rawKey"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override async Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true)
        {
            var key = await SubtleCrypto.ImportKey("raw", rawKey, Algorithm.AESCBC, extractable, new string[] { "encrypt", "decrypt" });
            return new BrowserAESCBCKey(key, rawKey.Length * 8, extractable);
        }
        /// <summary>
        /// Export an AES-CBC key
        /// </summary>
        public override async Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            await using var ret = await SubtleCrypto.ExportKeyRaw(jsKey.Key);
            return await ret.ReadBytes();
        }
    }
}
