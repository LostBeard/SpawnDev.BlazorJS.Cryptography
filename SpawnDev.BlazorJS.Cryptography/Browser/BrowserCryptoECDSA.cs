
using SpawnDev.BlazorJS.Cryptography.Browser;
using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserCrypto
    {
        /// <summary>
        /// Generate a new ECDSA key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var keyUsages = new string[] { "sign", "verify" };
            var key = await SubtleCrypto!.GenerateKey<CryptoKeyPairAsync>(new EcKeyGenParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
            return new BrowserECDSAKey(key, namedCurve, extractable, keyUsages);
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key)
        {
            if (key is not BrowserECDSAKey keyJS) throw new NotImplementedException();
            await using var publicKey = await keyJS.Key.Get_PublicKey();
            await using var arrayBuffer = await SubtleCrypto!.ExportKeySpki(publicKey!);
            return await arrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key)
        {
            if (key is not BrowserECDSAKey keyJS) throw new NotImplementedException();
            await using var privateKey = await keyJS.Key.Get_PrivateKey();
            await using var arrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey!);
            return await arrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Import an ECDSA public key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var keyUsagesPublicKey = new string[] { "verify" };
            await using var publicKey = await SubtleCrypto!.ImportKey("spki", publicKeySpkiData, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsagesPublicKey);
            var key = await CryptoKeyPairAsync.New(JSA);
            await key.Set_PublicKey(publicKey);
            return new BrowserECDSAKey(key, namedCurve, extractable, keyUsagesPublicKey);
        }
        /// <summary>
        /// Import an ECDSA public and private key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="privateKeyPkcs8Data"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var keyUsagesPrivateKey = new string[] { "sign" };
            var keyUsagesPublicKey = new string[] { "verify" };
            await using var privateKey = await SubtleCrypto!.ImportKey("pkcs8", privateKeyPkcs8Data, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsagesPrivateKey);
            await using var publicKey = await SubtleCrypto!.ImportKey("spki", publicKeySpkiData, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsagesPublicKey);
            var key = await CryptoKeyPairAsync.New(JSA);
            await key.Set_PublicKey(publicKey);
            await key.Set_PrivateKey(privateKey);
            return new BrowserECDSAKey(key, namedCurve, extractable, keyUsagesPublicKey.Concat(keyUsagesPrivateKey).ToArray());
        }
        /// <summary>
        /// Verify a data signature
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = HashName.SHA512)
        {
            if (key is not BrowserECDSAKey keyJS) throw new NotImplementedException();
            await using var publicKey = await keyJS!.Key.Get_PublicKey();
            await using var signatureArrayBuffer = await ArrayBufferAsync.New(JSA, signature);
            var ret = await SubtleCrypto!.Verify(new EcdsaParams { Hash = hashName }, publicKey!, signatureArrayBuffer, data);
            return ret;
        }
        /// <summary>
        /// Sign data using an ECDSA key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = HashName.SHA512)
        {
            if (key is not BrowserECDSAKey keyJS) throw new NotImplementedException();
            await using var privateKey = await keyJS!.Key.Get_PrivateKey();
            await using var signature = await SubtleCrypto!.Sign(new EcdsaParams { Hash = hashName }, privateKey, data);
            return await signature.ReadBytes();
        }
    }
}
