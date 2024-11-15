using SpawnDev.BlazorJS.Cryptography.Browser;
using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.RemoteJSRuntime;
using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class BrowserCrypto
    {
        /// <summary>
        /// Generates a new ECDH crypto key
        /// </summary>
        /// <param name="namedCurve">
        /// A string representing the name of the elliptic curve to use. This may be any of the following names for NIST-approved curves:<br/>
        /// P-256<br/>
        /// P-384<br/>
        /// P-521
        /// </param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDHKey> GenerateECDHKey(string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var keyUsages = new string[] { "deriveBits", "deriveKey" };
            var key = await SubtleCrypto!.GenerateKey<CryptoKeyPairAsync>(new EcKeyGenParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, keyUsages);
            return new BrowserECDHKey(key, namedCurve, extractable, keyUsages);
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPublicKeySpki(PortableECDHKey key)
        {
            if (key is not BrowserECDHKey keyJS) throw new NotImplementedException();
            var publicKey = await keyJS.Key.Get_PublicKey();
            await using var arrayBuffer = await SubtleCrypto.ExportKeySpki(publicKey!);
            return await arrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key)
        {
            if (key is not BrowserECDHKey keyJS) throw new NotImplementedException();
            await using var privateKey = await keyJS.Key.Get_PrivateKey();
            await using var arrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey!);
            return await arrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Import an ECDH public key
        /// </summary>
        /// <param name="publicKeySpki"></param>
        /// <param name="namedCurve">
        /// A string representing the name of the elliptic curve to use. This may be any of the following names for NIST-approved curves:<br/>
        /// P-256<br/>
        /// P-384<br/>
        /// P-521
        /// </param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var keyUsages = new string[] { };
            var publicKey = await SubtleCrypto!.ImportKey("spki", publicKeySpki, new EcKeyImportParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, keyUsages);
            var key = await CryptoKeyPairAsync.New(JSA);
            await key.Set_PublicKey(publicKey);
            return new BrowserECDHKey(key, namedCurve, extractable, keyUsages);
        }
        /// <summary>
        /// Import an ECDH public and private key
        /// </summary>
        /// <param name="publicKeySpki"></param>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="namedCurve">
        /// A string representing the name of the elliptic curve to use. This may be any of the following names for NIST-approved curves:<br/>
        /// P-256<br/>
        /// P-384<br/>
        /// P-521
        /// </param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var keyUsages = new string[] { "deriveBits", "deriveKey" };
            var privateKey = await SubtleCrypto!.ImportKey("pkcs8", privateKeyPkcs8, new EcKeyImportParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, keyUsages);
            var publicKey = await SubtleCrypto!.ImportKey("spki", publicKeySpki, new EcKeyImportParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, new string[] { });
            var key = await CryptoKeyPairAsync.New(JSA);
            await key.Set_PublicKey(publicKey);
            await key.Set_PrivateKey(privateKey);
            return new BrowserECDHKey(key, namedCurve, extractable, keyUsages);
        }
        /// <summary>
        /// Creates a shared secret that is cross-platform compatible
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <param name="bitLength">Number of bits to derive.<br/>For compatibility, this should be a multiple of 8</param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="Exception"></exception>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength)
        {
            if (localPartyKey is not BrowserECDHKey localPartyKeyJS) throw new NotImplementedException();
            if (otherPartyKey is not BrowserECDHKey otherPartyKeyJS) throw new NotImplementedException();
            if (bitLength <= 0) throw new ArgumentOutOfRangeException(nameof(bitLength));
            await using var localPartyPrivateKey = await localPartyKeyJS!.Key.Get_PrivateKey();
            if (localPartyPrivateKey == null) throw new ArgumentNullException($"localPartyKey.Key.PrivateKey cannot be null");
            await using var otherPartyPublicKey = await otherPartyKeyJS!.Key.Get_PublicKey();
            if (otherPartyPublicKey == null) throw new ArgumentNullException($"otherPartyKey.Key.PublicKey cannot be null");
            await using var sharedSecret = await SubtleCrypto!.DeriveBits(new EcdhKeyDeriveParamsAsync { Public = otherPartyPublicKey }, localPartyPrivateKey, bitLength);
            var sharedSecretBytes = await sharedSecret.ReadBytes();
            return sharedSecretBytes;
        }
        /// <summary>
        /// Creates a shared secret that is cross-platform compatible
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey)
        {
            // chooses the largest bit length divisible by 8 for best compatibility as recommended in MDN SubtleCrypto docs
            var bitLength = NamedCurveBitLength(localPartyKey.NamedCurve, true);
            return DeriveBits(localPartyKey, otherPartyKey, bitLength);
        }
    }
}
