
using SpawnDev.BlazorJS.Cryptography.DotNet;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
    {
        /// <summary>
        /// Generate a new Ed25519 key pair
        /// </summary>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override Task<PortableEd25519Key> GenerateEd25519Key(bool extractable = true)
        {
            var (publicKey, seed) = Ed25519Managed.GenerateKeyPair();
            return Task.FromResult<PortableEd25519Key>(new DotNetEd25519Key(seed, publicKey));
        }
        /// <summary>
        /// Exports the public key in Spki format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public override Task<byte[]> ExportPublicKeySpki(PortableEd25519Key key)
        {
            if (key is not DotNetEd25519Key keyNet) throw new NotImplementedException();
            return Task.FromResult(Ed25519Managed.EncodeSpki(keyNet.PublicKeyBytes));
        }
        /// <summary>
        /// Exports the private key in Pkcs8 format
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public override Task<byte[]> ExportPrivateKeyPkcs8(PortableEd25519Key key)
        {
            if (key is not DotNetEd25519Key keyNet) throw new NotImplementedException();
            if (keyNet.Seed == null) throw new InvalidOperationException("Key does not contain a private key");
            return Task.FromResult(Ed25519Managed.EncodePkcs8(keyNet.Seed));
        }
        /// <summary>
        /// Import an Ed25519 public key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override Task<PortableEd25519Key> ImportEd25519Key(byte[] publicKeySpkiData, bool extractable = true)
        {
            var publicKey = Ed25519Managed.DecodeSpki(publicKeySpkiData);
            return Task.FromResult<PortableEd25519Key>(new DotNetEd25519Key(publicKey));
        }
        /// <summary>
        /// Import an Ed25519 public and private key
        /// </summary>
        /// <param name="publicKeySpkiData"></param>
        /// <param name="privateKeyPkcs8Data"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override Task<PortableEd25519Key> ImportEd25519Key(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, bool extractable = true)
        {
            var publicKey = Ed25519Managed.DecodeSpki(publicKeySpkiData);
            var seed = Ed25519Managed.DecodePkcs8(privateKeyPkcs8Data);
            return Task.FromResult<PortableEd25519Key>(new DotNetEd25519Key(seed, publicKey));
        }
        /// <summary>
        /// Sign data using an Ed25519 key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public override Task<byte[]> Sign(PortableEd25519Key key, byte[] data)
        {
            if (key is not DotNetEd25519Key keyNet) throw new NotImplementedException();
            if (keyNet.Seed == null) throw new InvalidOperationException("Key does not contain a private key");
            return Task.FromResult(Ed25519Managed.Sign(keyNet.Seed, data));
        }
        /// <summary>
        /// Verify an Ed25519 signature
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public override Task<bool> Verify(PortableEd25519Key key, byte[] data, byte[] signature)
        {
            if (key is not DotNetEd25519Key keyNet) throw new NotImplementedException();
            return Task.FromResult(Ed25519Managed.Verify(keyNet.PublicKeyBytes, data, signature));
        }
    }
}
