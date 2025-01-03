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
        public async Task<Uint8ArrayAsync> Encrypt(PortableAESCBCKey key, Uint8ArrayAsync plainBytes, Uint8ArrayAsync iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            Uint8ArrayAsync encryptedUint8Array;
            if (padding == AESCBCPadding.None)
            {
                var dataLength = await plainBytes.Get_Length();
                if (dataLength % AES_CBC_BLOCK_SIZE != 0)
                {
                    throw new Exception($"{plainBytes} length must be a multiple of 16 when using no padding.");
                }
                await using var encryptedArrayBuffer = await SubtleCrypto.Encrypt(new AesCbcParamsAsync { Iv = iv }, jsKey!.Key, plainBytes);
                encryptedUint8Array = await Uint8ArrayAsync.New(JSA, encryptedArrayBuffer);
                var encryptedLength = await encryptedArrayBuffer.Get_ByteLength();
                var tmp = await encryptedUint8Array.SubArray(0, encryptedLength - AES_CBC_BLOCK_SIZE);
                await encryptedUint8Array.DisposeAsync();
                encryptedUint8Array = tmp;
            }
            else
            {
                await using var encryptedArrayBuffer = await SubtleCrypto.Encrypt(new AesCbcParamsAsync { Iv = iv }, jsKey!.Key, plainBytes);
                encryptedUint8Array = await Uint8ArrayAsync.New(JSA, encryptedArrayBuffer);
            }
            if (!prependIV)
            {
                return encryptedUint8Array;
            }
            var ivLength = await iv.Get_Length();
            var encryptedDataWithIvLength = await encryptedUint8Array.Get_Length() + ivLength;
            var result = await Uint8ArrayAsync.New(JSA, encryptedDataWithIvLength);
            // + iv
            await result.Set(iv, 0);
            // + encrypted data
            await result.Set(encryptedUint8Array, ivLength);
            await encryptedUint8Array.DisposeAsync();
            return result;
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public override async Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            await using var ivUint8Array = await Uint8ArrayAsync.New(JSA, iv);
            await using var dataUint8Array = await Uint8ArrayAsync.New(JSA, plainBytes);
            await using var decrypted = await Encrypt(key, dataUint8Array, ivUint8Array, prependIV, padding);
            return await decrypted.ReadBytes();
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            var iv = RandomBytes(16);
            return Encrypt(key, plainBytes, iv, prependIV, padding);
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        public async Task<Uint8ArrayAsync> Encrypt(PortableAESCBCKey key, Uint8ArrayAsync plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            var iv = RandomBytes(16);
            await using var ivUint8Array = await Uint8ArrayAsync.New(JSA, iv);
            return await Encrypt(key, plainBytes, ivUint8Array, prependIV, padding);
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be supplied separately from the encrypted data
        /// </summary>
        public async Task<Uint8ArrayAsync> Decrypt(PortableAESCBCKey key, Uint8ArrayAsync encryptedData, Uint8ArrayAsync iv, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not BrowserAESCBCKey jsKey) throw new NotImplementedException();
            if (padding == AESCBCPadding.None)
            {
                // PKS7 padding must be added because SubtleCrypto's implementation of AES-CBC requires it
                var dataLength = await encryptedData.Get_Length();
                // PKS7 padding must be added because SubtleCrypto's implementation of AES-CBC requires it
                if (dataLength % AES_CBC_BLOCK_SIZE != 0)
                {
                    throw new Exception($"{encryptedData} length must be a multiple of 16 when using no padding.");
                }
                // create a Uint8Array to hold the padded data
                await using var paddedData = await Uint8ArrayAsync.New(JSA, dataLength + AES_CBC_BLOCK_SIZE);
                await paddedData.Set(encryptedData, 0);
                // padding starts as a byte array of size paddingSize where each byte is the paddingSize
                await using var paddingData = await Uint8ArrayAsync.New(JSA, AES_CBC_BLOCK_SIZE);
                await paddingData.FillVoid((byte)AES_CBC_BLOCK_SIZE);
                // use the last paddingSize bytes of data is the iv
                await using var padBlockIv = await encryptedData.Slice(-AES_CBC_BLOCK_SIZE);
                await using var padBlock = await Encrypt(jsKey, paddingData, padBlockIv, false, AESCBCPadding.None);
                await paddedData.Set(padBlock, dataLength);
                // decrypt
                var decryptedArrayBuffer = await SubtleCrypto.Decrypt(new AesCbcParamsAsync { Iv = iv }, jsKey.Key, paddedData);
                // return the decrypted data as a Uint8Array
                return await Uint8ArrayAsync.New(JSA, decryptedArrayBuffer);
            }
            else
            {
                await using var arrayBuffer = await SubtleCrypto.Decrypt(new AesCbcParamsAsync { Iv = iv }, jsKey!.Key, encryptedData);
                return await Uint8ArrayAsync.New(JSA, arrayBuffer);
            }
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be supplied separately from the encrypted data
        /// </summary>
        public override async Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            await using var ivUint8Array = await Uint8ArrayAsync.New(JSA, iv);
            await using var encryptedDataUint8Array = await Uint8ArrayAsync.New(JSA, encryptedData);
            await using var decrypted = await Decrypt(key, encryptedDataUint8Array, ivUint8Array, padding);
            return await decrypted.ReadBytes();
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be prepended to the encrypted data
        /// </summary>
        public override async Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            await using var encryptedDataUint8Array = await Uint8ArrayAsync.New(JSA, encryptedData);
            await using var decrypted = await Decrypt(key, encryptedDataUint8Array, padding);
            return await decrypted.ReadBytes();
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key<br/>
        /// This method expects the IV to be prepended to the encrypted data
        /// </summary>
        public async Task<Uint8ArrayAsync> Decrypt(PortableAESCBCKey key, Uint8ArrayAsync encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            await using var iv = await encryptedData.Slice(0, 16);
            await using var encrypted = await encryptedData.Slice(16);
            return await Decrypt(key, encrypted, iv, padding);
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
