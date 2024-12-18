
using SpawnDev.BlazorJS.Cryptography.DotNet;
using SpawnDev.BlazorJS.JSObjects;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
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
            var eccurve = NamedCurveToECCurve(namedCurve);
            var key = ECDiffieHellman.Create(eccurve);
            return new DotNetECDHKey(key);
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> ExportPublicKeySpki(PortableECDHKey key)
        {
            if (key is DotNetECDHKey keyNet)
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
        public override async Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key)
        {
            if (key is DotNetECDHKey keyNet)
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
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = NamedCurve.P521, bool extractable = true)
        {
            var key = ECDiffieHellman.Create();
            key.ImportSubjectPublicKeyInfo(publicKeySpki, out _);
            return new DotNetECDHKey(key);
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
            var key = ECDiffieHellman.Create();
            key.ImportPkcs8PrivateKey(privateKeyPkcs8, out _);
            return new DotNetECDHKey(key);
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
            if (localPartyKey is not DotNetECDHKey localPartyKeyNet) throw new NotImplementedException();
            if (otherPartyKey is not DotNetECDHKey otherPartyKeyNet) throw new NotImplementedException();
            if (bitLength <= 0) throw new ArgumentOutOfRangeException(nameof(bitLength));
            if (localPartyKeyNet?.Key == null) throw new ArgumentNullException($"localPartyKey.Key cannot be null");
            if (otherPartyKeyNet?.Key?.PublicKey == null) throw new ArgumentNullException($"otherPartyKey.Key.PublicKey cannot be null");
            var ret = localPartyKeyNet!.Key.DeriveRawSecretAgreement(otherPartyKeyNet!.Key.PublicKey);
            var retBitLength = ret.Length * 8;
            if (retBitLength < bitLength) throw new Exception($"Requested {bitLength} exceeds the max bitLength {retBitLength}");
            var requestedByteLength = (int)Math.Ceiling(bitLength / 8d);
            if (requestedByteLength == retBitLength) return ret;
            return ret[..requestedByteLength];
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
