using SpawnDev.BlazorJS.JSObjects;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class PortableCrypto
    {
        /// <summary>
        /// Generate a new ECDSA key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            if (OperatingSystem.IsBrowser())
            {
                var keyUsages = new string[] { "sign", "verify" };
                var key = await SubtleCrypto!.GenerateKey<CryptoKeyPair>(new EcKeyGenParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
                return new PortableECDSAKeyJS(key);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var eccurve = NamedCurveToECCurve(namedCurve);
                var key = ECDsa.Create(eccurve);
                return new PortableECDSAKeyNet(key);
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key)
        {
            if (key is PortableECDSAKeyJS keyECDSAJS)
            {
                using var publicKey = keyECDSAJS.Key.PublicKey;
                using var arrayBuffer = await SubtleCrypto!.ExportKeySpki(publicKey!);
                return arrayBuffer.ReadBytes();
            }
            else if (key is PortableECDSAKeyNet keyECDSANet)
            {
                return keyECDSANet.Key.ExportSubjectPublicKeyInfo();
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key)
        {
            if (key is PortableECDSAKeyJS keyJS)
            {
                using var privateKey = keyJS.Key.PrivateKey;
                using var arrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey!);
                return arrayBuffer.ReadBytes();
            }
            else if (key is PortableECDSAKeyNet keyNet)
            {
                return keyNet.Key.ExportPkcs8PrivateKey();
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Import an ECDSA public key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            if (OperatingSystem.IsBrowser())
            {
                var keyUsages = new string[] { };
                var publicKey = await SubtleCrypto!.ImportKey<CryptoKey>("spki", publicKeySpkiData, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
                var key = new CryptoKeyPair
                {
                    PublicKey = publicKey,
                };
                return new PortableECDSAKeyJS(key);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(publicKeySpkiData, out _);
                return new PortableECDSAKeyNet(key);
            }
            throw new NotImplementedException();
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
        public async Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            if (OperatingSystem.IsBrowser())
            {
                var keyUsages = new string[] { "deriveBits", "deriveKey" };
                var privateKey = await SubtleCrypto!.ImportKey<CryptoKey>("pkcs8", privateKeyPkcs8Data, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, keyUsages);
                var publicKey = await SubtleCrypto!.ImportKey<CryptoKey>("spki", publicKeySpkiData, new EcKeyImportParams { Name = Algorithm.ECDSA, NamedCurve = namedCurve }, extractable, new string[] { });
                var key = new CryptoKeyPair
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                };
                return new PortableECDSAKeyJS(key);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(publicKeySpkiData, out _);
                key.ImportPkcs8PrivateKey(privateKeyPkcs8Data, out _);
                return new PortableECDSAKeyNet(key);
            }
            throw new NotImplementedException();
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
        public async Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = HashName.SHA512)
        {
            if (OperatingSystem.IsBrowser())
            {
                var keyJS = key as PortableECDSAKeyJS;
                using var publicKey = keyJS!.Key.PublicKey!;
                using var signatureUint8Array = new Uint8Array(signature);
                using var signatureArrayBuffer = signatureUint8Array.Buffer;
                var ret = await SubtleCrypto!.Verify(new EcdsaParams { Hash = hashName }, publicKey, signatureArrayBuffer, data);
                return ret;
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var hashAlgorithm = HashNameToHashAlgorithmName(hashName);
                var keyNet = key as PortableECDSAKeyNet;
                var verified = keyNet!.Key.VerifyData(data, signature, hashAlgorithm);
                return verified;
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Sign data using an ECDSA key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = HashName.SHA512)
        {
            if (OperatingSystem.IsBrowser())
            {
                var keyJS = key as PortableECDSAKeyJS;
                using var privateKey = keyJS!.Key.PrivateKey!;
                using var signature = await SubtleCrypto!.Sign(new EcdsaParams { Hash = hashName }, privateKey, data);
                return signature.ReadBytes();
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var hashAlgorithm = HashNameToHashAlgorithmName(hashName);
                var keyNet = key as PortableECDSAKeyNet;
                var signature = keyNet!.Key.SignData(data, hashAlgorithm);
                return signature;
            }
            throw new NotImplementedException();
        }
    }
}
