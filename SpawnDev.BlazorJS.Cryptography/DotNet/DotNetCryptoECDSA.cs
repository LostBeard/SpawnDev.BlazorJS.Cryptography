
using SpawnDev.BlazorJS.Cryptography.DotNet;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
    {
        /// <summary>
        /// Generate a new ECDSA key
        /// </summary>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var eccurve = NamedCurveToECCurve(namedCurve);
            var key = ECDsa.Create(eccurve);
            return Task.FromResult<PortableECDSAKey>(new DotNetECDSAKey(key));
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key)
        {
            if (key is not DotNetECDSAKey keyNet) throw new NotImplementedException();
            return Task.FromResult(keyNet.Key.ExportSubjectPublicKeyInfo());
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key)
        {
            if (key is not DotNetECDSAKey keyNet) throw new NotImplementedException();
            return Task.FromResult(keyNet.Key.ExportPkcs8PrivateKey());
        }
        /// <summary>
        /// Import an ECDSA public key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="namedCurve"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeySpkiData, out _);
            return Task.FromResult<PortableECDSAKey>(new DotNetECDSAKey(key));
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
        public override Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeySpkiData, out _);
            key.ImportPkcs8PrivateKey(privateKeyPkcs8Data, out _);
            return Task.FromResult<PortableECDSAKey>(new DotNetECDSAKey(key));
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
        public override Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = HashName.SHA512)
        {
            if (key is not DotNetECDSAKey keyNet) throw new NotImplementedException();
            var hashAlgorithm = HashNameToHashAlgorithmName(hashName);
            var verified = keyNet!.Key.VerifyData(data, signature, hashAlgorithm);
            return Task.FromResult(verified);
        }
        /// <summary>
        /// Sign data using an ECDSA key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="hashName"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = HashName.SHA512)
        {
            if (key is not DotNetECDSAKey keyNet) throw new NotImplementedException();
            var hashAlgorithm = HashNameToHashAlgorithmName(hashName);
            var signature = keyNet!.Key.SignData(data, hashAlgorithm);
            return Task.FromResult(signature);
        }
    }
}
