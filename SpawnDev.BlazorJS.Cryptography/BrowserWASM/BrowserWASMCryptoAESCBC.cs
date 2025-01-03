using SpawnDev.BlazorJS.Cryptography.BrowserWASM;
using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserWASMCrypto
    {
        /// <summary>
        /// Generate an AES-CBC key
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override async Task<PortableAESCBCKey> GenerateAESCBCKey(int keySize, bool extractable = true)
        {
            var keyUsages = new string[] { "encrypt", "decrypt" };
            var key = await SubtleCrypto.GenerateKey<CryptoKey>(new AesKeyGenParams { Name = Algorithm.AESCBC, Length = keySize }, extractable, keyUsages);
            return new BrowserWASMAESCBCKey(key, keySize);
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public async Task<Uint8Array> Encrypt(PortableAESCBCKey key, Uint8Array plainBytes, Uint8Array iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserWASMAESCBCKey jsKey) throw new NotImplementedException(); 
            if (padding == AESCBCPadding.None)
            {
                if (plainBytes.Length % AES_CBC_BLOCK_SIZE != 0)
                {
                    throw new Exception($"{plainBytes} length must be a multiple of 16 when using no padding.");
                }
            }
            using var ret = await SubtleCrypto.Encrypt(new AesCbcParams { Iv = iv }, jsKey!.Key, plainBytes);
            var retUint8Array = new Uint8Array(ret);
            if (padding == AESCBCPadding.None)
            {
                // Trim PKCS#7 padding from the result.
                // The input must be a multiple of the block size when using no padding so the added padding size is equal to the block size
                var tmp = retUint8Array.SubArray(0, ret.ByteLength - AES_CBC_BLOCK_SIZE);
                retUint8Array.Dispose();
                retUint8Array = tmp;
            }
            if (!prependIV)
            {
                return retUint8Array;
            }
            var encryptedDataLength = retUint8Array.Length + iv.Length;
            var result = new Uint8Array(encryptedDataLength);
            // + iv
            result.Set(iv, 0);
            // + encrypted data
            result.Set(retUint8Array, iv.Length);
            retUint8Array.Dispose();
            return result;
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public override async Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            using var ivUint8Array = new Uint8Array(iv);
            using var dataUint8Array = new Uint8Array(plainBytes);
            using var decrypted = await Encrypt(key, dataUint8Array, ivUint8Array, prependIV, padding);
            return decrypted.ReadBytes();
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserWASMAESCBCKey jsKey) throw new NotImplementedException();
            var iv = RandomBytes(16);
            return Encrypt(key, plainBytes, iv, prependIV, padding);
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public async Task<Uint8Array> Encrypt(PortableAESCBCKey key, Uint8Array plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserWASMAESCBCKey jsKey) throw new NotImplementedException();
            var iv = RandomBytes(16);
            using var ivUint8Array = new Uint8Array(iv);
            return await Encrypt(key, plainBytes, ivUint8Array, prependIV, padding);
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be supplied separately from the encrypted data
        /// </summary>
        public override async Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            using var ivUint8Array = new Uint8Array(iv);
            using var encryptedDataUint8Array = new Uint8Array(encryptedData);
            using var decrypted = await Decrypt(key, encryptedDataUint8Array, ivUint8Array, padding);
            return decrypted.ReadBytes();
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be supplied separately from the encrypted data
        /// </summary>
        public async Task<Uint8Array> Decrypt(PortableAESCBCKey key, Uint8Array encryptedData, Uint8Array iv, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserWASMAESCBCKey jsKey) throw new NotImplementedException();
            if (padding == AESCBCPadding.None)
            {
                var encryptedDataLength = encryptedData.ByteLength;
                // PKS7 padding must be added because SubtleCrypto's implementation of AES-CBC requires it
                if (encryptedDataLength % AES_CBC_BLOCK_SIZE != 0)
                {
                    throw new Exception($"{encryptedData} length must be a multiple of 16 when using no padding.");
                }
                // create a Uint8Array to hold the padded data
                using var paddedData = new Uint8Array(AES_CBC_BLOCK_SIZE + encryptedDataLength);
                paddedData.Set(encryptedData, 0);
                // padding starts as a byte array of size paddingSize where each byte is the paddingSize
                using var paddingData = new Uint8Array(AES_CBC_BLOCK_SIZE);
                paddingData.FillVoid((byte)AES_CBC_BLOCK_SIZE);
                // use the last paddingSize bytes of data is the iv
                using var padBlockIv = encryptedData.Slice(-AES_CBC_BLOCK_SIZE);
                // encrypt the padding data
                using var padBlock = await Encrypt(jsKey, paddingData, padBlockIv, false, AESCBCPadding.None);
                paddedData.Set(padBlock, encryptedDataLength);
                // decrypt
                var decryptedArrayBuffer = await SubtleCrypto.Decrypt(new AesCbcParams { Iv = iv }, jsKey.Key, paddedData);
                // return the decrypted data as a Uint8Array
                return new Uint8Array(decryptedArrayBuffer);
            }
            else
            {
                using var arrayBuffer = await SubtleCrypto.Decrypt(new AesCbcParams { Iv = iv }, jsKey!.Key, encryptedData);
                return new Uint8Array(arrayBuffer);
            }
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be prepended to the encrypted data
        /// </summary>
        public override async Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            using var encryptedDataUint8Array = new Uint8Array(encryptedData);
            using var decrypted = await Decrypt(key, encryptedDataUint8Array, padding);
            return decrypted.ReadBytes();
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be prepended to the encrypted data
        /// </summary>
        public async Task<Uint8Array> Decrypt(PortableAESCBCKey key, Uint8Array encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            using var iv = encryptedData.Slice(0, 16);
            using var encrypted = encryptedData.Slice(16);
            return await Decrypt(key, encrypted, iv, padding);
        }
        /// <summary>
        /// Imports an AES-CBC key from a byte array
        /// </summary>
        /// <param name="rawKey"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override async Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true)
        {
            var key = await SubtleCrypto.ImportKey("raw", rawKey, Algorithm.AESCBC, extractable, new string[] { "encrypt", "decrypt" });
            return new BrowserWASMAESCBCKey(key, rawKey.Length * 8);
        }
        /// <summary>
        /// Exports an AES-CBC key as a byte array
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key)
        {
            if (key is not BrowserWASMAESCBCKey jsKey) throw new NotImplementedException();
            using var ret = await SubtleCrypto.ExportKeyRaw(jsKey.Key);
            return ret.ReadBytes();
        }
    }
}
