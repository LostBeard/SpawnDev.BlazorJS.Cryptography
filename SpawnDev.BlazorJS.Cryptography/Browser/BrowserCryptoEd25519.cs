
using SpawnDev.BlazorJS.Cryptography.Browser;
using SpawnDev.BlazorJS.Cryptography.DotNet;
using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserCrypto
    {
        /// <summary>
        /// Cached detection: null = untested, true = WebCrypto Ed25519 available, false = fallback to managed
        /// </summary>
        private static bool? _ed25519Supported;

        /// <summary>
        /// Generate a new Ed25519 key pair. Uses WebCrypto when available, falls back to managed C# implementation.
        /// </summary>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override async Task<PortableEd25519Key> GenerateEd25519Key(bool extractable = true)
        {
            if (_ed25519Supported != false)
            {
                try
                {
                    var keyUsages = new string[] { "sign", "verify" };
                    var key = await SubtleCrypto!.GenerateKey<CryptoKeyPairAsync>(new EcKeyGenParams { Name = Algorithm.Ed25519 }, extractable, keyUsages);
                    _ed25519Supported = true;
                    return new BrowserEd25519Key(key, extractable, keyUsages);
                }
                catch
                {
                    _ed25519Supported = false;
                }
            }
            var (publicKey, seed) = Ed25519Managed.GenerateKeyPair();
            return new DotNetEd25519Key(seed, publicKey);
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public override async Task<byte[]> ExportPublicKeySpki(PortableEd25519Key key)
        {
            if (key is BrowserEd25519Key keyJS)
            {
                await using var publicKey = await keyJS.Key.Get_PublicKey();
                await using var arrayBuffer = await SubtleCrypto!.ExportKeySpki(publicKey!);
                return await arrayBuffer.ReadBytes();
            }
            if (key is DotNetEd25519Key keyNet)
                return Ed25519Managed.EncodeSpki(keyNet.PublicKeyBytes);
            throw new NotImplementedException();
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public override async Task<byte[]> ExportPrivateKeyPkcs8(PortableEd25519Key key)
        {
            if (key is BrowserEd25519Key keyJS)
            {
                await using var privateKey = await keyJS.Key.Get_PrivateKey();
                await using var arrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey!);
                return await arrayBuffer.ReadBytes();
            }
            if (key is DotNetEd25519Key keyNet)
            {
                if (keyNet.Seed == null) throw new InvalidOperationException("Key does not contain a private key");
                return Ed25519Managed.EncodePkcs8(keyNet.Seed);
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Import an Ed25519 public key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override async Task<PortableEd25519Key> ImportEd25519Key(byte[] publicKeySpkiData, bool extractable = true)
        {
            if (_ed25519Supported != false)
            {
                try
                {
                    var keyUsagesPublicKey = new string[] { "verify" };
                    await using var publicKey = await SubtleCrypto!.ImportKey("spki", publicKeySpkiData, new CryptoImportParams { Name = Algorithm.Ed25519 }, extractable, keyUsagesPublicKey);
                    var key = await CryptoKeyPairAsync.New(JSA);
                    await key.Set_PublicKey(publicKey);
                    _ed25519Supported = true;
                    return new BrowserEd25519Key(key, extractable, keyUsagesPublicKey);
                }
                catch
                {
                    _ed25519Supported = false;
                }
            }
            var pubBytes = Ed25519Managed.DecodeSpki(publicKeySpkiData);
            return new DotNetEd25519Key(pubBytes);
        }
        /// <summary>
        /// Import an Ed25519 public and private key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="privateKeyPkcs8Data"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override async Task<PortableEd25519Key> ImportEd25519Key(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, bool extractable = true)
        {
            if (_ed25519Supported != false)
            {
                try
                {
                    var keyUsagesPrivateKey = new string[] { "sign" };
                    var keyUsagesPublicKey = new string[] { "verify" };
                    await using var privateKey = await SubtleCrypto!.ImportKey("pkcs8", privateKeyPkcs8Data, new CryptoImportParams { Name = Algorithm.Ed25519 }, extractable, keyUsagesPrivateKey);
                    await using var publicKey = await SubtleCrypto!.ImportKey("spki", publicKeySpkiData, new CryptoImportParams { Name = Algorithm.Ed25519 }, extractable, keyUsagesPublicKey);
                    var key = await CryptoKeyPairAsync.New(JSA);
                    await key.Set_PublicKey(publicKey);
                    await key.Set_PrivateKey(privateKey);
                    _ed25519Supported = true;
                    return new BrowserEd25519Key(key, extractable, keyUsagesPublicKey.Concat(keyUsagesPrivateKey).ToArray());
                }
                catch
                {
                    _ed25519Supported = false;
                }
            }
            var pubBytes = Ed25519Managed.DecodeSpki(publicKeySpkiData);
            var seed = Ed25519Managed.DecodePkcs8(privateKeyPkcs8Data);
            return new DotNetEd25519Key(seed, pubBytes);
        }
        /// <summary>
        /// Sign data using an Ed25519 key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public override async Task<byte[]> Sign(PortableEd25519Key key, byte[] data)
        {
            if (key is BrowserEd25519Key keyJS)
            {
                await using var privateKey = await keyJS!.Key.Get_PrivateKey();
                await using var signature = await SubtleCrypto!.Sign(new CryptoSignParams { Name = Algorithm.Ed25519 }, privateKey, data);
                return await signature.ReadBytes();
            }
            if (key is DotNetEd25519Key keyNet)
            {
                if (keyNet.Seed == null) throw new InvalidOperationException("Key does not contain a private key");
                return Ed25519Managed.Sign(keyNet.Seed, data);
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Verify an Ed25519 signature
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public override async Task<bool> Verify(PortableEd25519Key key, byte[] data, byte[] signature)
        {
            if (key is BrowserEd25519Key keyJS)
            {
                await using var publicKey = await keyJS!.Key.Get_PublicKey();
                await using var signatureArrayBuffer = await ArrayBufferAsync.New(JSA, signature);
                return await SubtleCrypto!.Verify(new CryptoSignParams { Name = Algorithm.Ed25519 }, publicKey!, signatureArrayBuffer, data);
            }
            if (key is DotNetEd25519Key keyNet)
                return Ed25519Managed.Verify(keyNet.PublicKeyBytes, data, signature);
            throw new NotImplementedException();
        }
    }
}
