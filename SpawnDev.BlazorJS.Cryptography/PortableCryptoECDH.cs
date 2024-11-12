using SpawnDev.BlazorJS.JSObjects;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class PortableCrypto
    {
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
        public async Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength)
        {
            if (bitLength <= 0) throw new ArgumentOutOfRangeException(nameof(bitLength));
            if (OperatingSystem.IsBrowser())
            {
                var localPartyKeyJS = localPartyKey as PortableECDHKeyJS;
                using var localPartyPrivateKey = localPartyKeyJS!.Key.PrivateKey;
                if (localPartyPrivateKey == null) throw new ArgumentNullException($"localPartyKey.Key.PrivateKey cannot be null");
                var otherPartyKeyJS = otherPartyKey as PortableECDHKeyJS;
                using var otherPartyPublicKey = otherPartyKeyJS!.Key.PublicKey;
                if (otherPartyPublicKey == null) throw new ArgumentNullException($"otherPartyKey.Key.PublicKey cannot be null");
                using var sharedSecret = await SubtleCrypto!.DeriveBits(new EcdhKeyDeriveParams { Public = otherPartyPublicKey }, localPartyPrivateKey, bitLength);
                var sharedSecretBytes = sharedSecret.ReadBytes();
                return sharedSecretBytes;
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var localPartyKeyNet = localPartyKey as PortableECDHKeyNet;
                if (localPartyKeyNet?.Key == null) throw new ArgumentNullException($"localPartyKey.Key cannot be null");
                var otherPartyKeyNet = otherPartyKey as PortableECDHKeyNet;
                if (otherPartyKeyNet?.Key?.PublicKey == null) throw new ArgumentNullException($"otherPartyKey.Key.PublicKey cannot be null");
                var ret = localPartyKeyNet!.Key.DeriveRawSecretAgreement(otherPartyKeyNet!.Key.PublicKey);
                var retBitLength = ret.Length * 8;
                if (retBitLength < bitLength) throw new Exception($"Requested {bitLength} exceeds the max bitLength {retBitLength}");
                var requestedByteLength = (int)Math.Ceiling(bitLength / 8d);
                if (requestedByteLength == retBitLength) return ret;
                return ret[..requestedByteLength];
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Creates a shared secret that is cross-platform compatible
        /// </summary>
        /// <param name="localPartyKey"></param>
        /// <param name="otherPartyKey"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey)
        {
            // chooses the largest bit length divisible by 8 for best compatibility as recommended in MDN SubtleCrypto docs
            var bitLength = NamedCurveBitLength(localPartyKey.NamedCurve, true);
            return DeriveBits(localPartyKey, otherPartyKey, bitLength);
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> ExportPublicKeySpki(PortableECDHKey key)
        {
            if (key is PortableECDHKeyJS keyJS)
            {
                using var publicKey = keyJS.Key.PublicKey;
                using var arrayBuffer = await SubtleCrypto!.ExportKeySpki(publicKey!);
                return arrayBuffer.ReadBytes();
            }
            else if (key is PortableECDHKeyNet keyNet)
            {
                return keyNet.Key.ExportSubjectPublicKeyInfo();
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key)
        {
            if (key is PortableECDHKeyJS keyJS)
            {
                using var privateKey = keyJS.Key.PrivateKey;
                using var arrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey!);
                return arrayBuffer.ReadBytes();
            }
            else if (key is PortableECDHKeyNet keyNet)
            {
                return keyNet.Key.ExportPkcs8PrivateKey();
            }
            throw new NotImplementedException();
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
        /// <param name="keyUsages"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = NamedCurve.P521, bool extractable = true, IEnumerable<string>? keyUsages = null)
        {
            if (OperatingSystem.IsBrowser())
            {
                keyUsages ??= new string[] { };
                var publicKey = await SubtleCrypto!.ImportKey<CryptoKey>("spki", publicKeySpki, new EcKeyImportParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, keyUsages);
                var key = new CryptoKeyPair
                {
                    PublicKey = publicKey,
                };
                return new PortableECDHKeyJS(key);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var key = ECDiffieHellman.Create();
                key.ImportSubjectPublicKeyInfo(publicKeySpki, out _);
                return new PortableECDHKeyNet(key);
            }
            throw new NotImplementedException();
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
        /// <param name="keyUsages"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = NamedCurve.P521, bool extractable = true, IEnumerable<string>? keyUsages = null)
        {
            if (OperatingSystem.IsBrowser())
            {
                keyUsages ??= new string[] { "deriveBits", "deriveKey" };
                var privateKey = await SubtleCrypto!.ImportKey<CryptoKey>("pkcs8", privateKeyPkcs8, new EcKeyImportParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, keyUsages);
                var publicKey = await SubtleCrypto!.ImportKey<CryptoKey>("spki", publicKeySpki, new EcKeyImportParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, new string[] { });
                var key = new CryptoKeyPair
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                };
                return new PortableECDHKeyJS(key);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var key = ECDiffieHellman.Create();
                key.ImportPkcs8PrivateKey(privateKeyPkcs8, out _);
                key.ImportSubjectPublicKeyInfo(publicKeySpki, out _);
                return new PortableECDHKeyNet(key);
            }
            throw new NotImplementedException();
        }
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
        /// <param name="keyUsages"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<PortableECDHKey> GenerateECDHKey(string namedCurve = NamedCurve.P521, bool extractable = true, IEnumerable<string>? keyUsages = null)
        {
            if (OperatingSystem.IsBrowser())
            {
                keyUsages ??= new string[] { "deriveBits", "deriveKey" };
                var key = await SubtleCrypto!.GenerateKey<CryptoKeyPair>(new EcKeyGenParams { Name = Algorithm.ECDH, NamedCurve = namedCurve }, extractable, keyUsages);
                return new PortableECDHKeyJS(key);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var eccurve = NamedCurveToECCurve(namedCurve);
                var key = ECDiffieHellman.Create(eccurve);
                return new PortableECDHKeyNet(key);
            }
            throw new NotImplementedException();
        }
    }
}
