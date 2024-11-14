
using SpawnDev.BlazorJS.Cryptography.BrowserWASM;
using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserWASMCrypto
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
            var key = await SubtleCrypto!.GenerateKey<CryptoKeyPair>(new EcKeyGenParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
            return new BrowserWASMECDSAKey(key);
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key)
        {
            if (key is not BrowserWASMECDSAKey keyJS) throw new NotImplementedException();
            using var publicKey = keyJS.Key.PublicKey;
            using var arrayBuffer = await SubtleCrypto!.ExportKeySpki(publicKey!);
            return arrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key)
        {
            if (key is not BrowserWASMECDSAKey keyJS) throw new NotImplementedException();
            using var privateKey = keyJS.Key.PrivateKey;
            using var arrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey!);
            return arrayBuffer.ReadBytes();
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
            var keyUsages = new string[] { };
            var publicKey = await SubtleCrypto!.ImportKey<CryptoKey>("spki", publicKeySpkiData, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
            var key = new CryptoKeyPair
            {
                PublicKey = publicKey,
            };
            return new BrowserWASMECDSAKey(key);
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
            var keyUsages = new string[] { "deriveBits", "deriveKey" };
            var privateKey = await SubtleCrypto!.ImportKey<CryptoKey>("pkcs8", privateKeyPkcs8Data, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
            var publicKey = await SubtleCrypto!.ImportKey<CryptoKey>("spki", publicKeySpkiData, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, new string[] { });
            var key = new CryptoKeyPair
            {
                PublicKey = publicKey,
                PrivateKey = privateKey,
            };
            return new BrowserWASMECDSAKey(key);
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
            if (key is not BrowserWASMECDSAKey keyJS) throw new NotImplementedException();
            using var publicKey = keyJS!.Key.PublicKey!;
            using var signatureUint8Array = new Uint8Array(signature);
            using var signatureArrayBuffer = signatureUint8Array.Buffer;
            var ret = await SubtleCrypto!.Verify(new EcdsaParams { Hash = hashName }, publicKey, signatureArrayBuffer, data);
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
            if (key is not BrowserWASMECDSAKey keyJS) throw new NotImplementedException();
            using var privateKey = keyJS!.Key.PrivateKey!;
            using var signature = await SubtleCrypto!.Sign(new EcdsaParams { Hash = hashName }, privateKey, data);
            return signature.ReadBytes();
        }
    }
}
