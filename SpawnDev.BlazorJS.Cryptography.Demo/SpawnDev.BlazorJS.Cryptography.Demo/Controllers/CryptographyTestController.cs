using Microsoft.AspNetCore.Mvc;

using System.Text;
using static SpawnDev.BlazorJS.Cryptography.Demo.Client.Pages.TestPage;

namespace SpawnDev.BlazorJS.Cryptography.Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CryptographyTestController : ControllerBase
    {

        DotNetCrypto DotNetCrypto;
        public CryptographyTestController(DotNetCrypto dotNetCrypto)
        {
            DotNetCrypto = dotNetCrypto;

        }
        static bool BeenInit = false;
        static PortableECDSAKey? ECDSAKey = null;
        static PortableECDHKey? ECDHKey = null;
        async Task InitAsync()
        {
            if (BeenInit) return;
            BeenInit = true;
            ECDSAKey = await DotNetCrypto.GenerateECDSAKey();
            ECDHKey = await DotNetCrypto.GenerateECDHKey();
        }

        [HttpGet("ecdsa")]
        public async Task<byte[]> GetECDSA()
        {
            await InitAsync();
            var publicKeyBytes = await DotNetCrypto.ExportPublicKeySpki(ECDSAKey!);
            return publicKeyBytes;
        }

        [HttpGet("ecdh")]
        public async Task<byte[]> GetECDH()
        {
            await InitAsync();
            var publicKeyBytes = await DotNetCrypto.ExportPublicKeySpki(ECDHKey!);
            return publicKeyBytes;
        }

        [HttpPost("identify")]
        public async Task<IEnumerable<string>> IdentifyPost(string[] data)
        {
            await InitAsync();
            var ret = "Hello world!!";
            return new string[] { ret };
        }

        [HttpPost("GetSharedSecret")]
        public async Task<byte[]> GetSharedSecret(GetSharedSecretArgs args)
        {
            await InitAsync();
            using var browsersECDHKey = await DotNetCrypto.ImportECDHKey(Convert.FromBase64String(args.SenderECDHPublicKeyB64));
            var sharedSecret = await DotNetCrypto.DeriveBits(ECDHKey!, browsersECDHKey);
            return sharedSecret;
        }

        [HttpPost("EncryptionTest")]
        public async Task<byte[]> EncryptionTest(EncryptionTestArgs args)
        {
            await InitAsync();
            using var browsersECDHKey = await DotNetCrypto.ImportECDHKey(Convert.FromBase64String(args.SenderECDHPublicKeyB64));
            var sharedSecret = await DotNetCrypto.DeriveBits(ECDHKey!, browsersECDHKey);
            using var encKey = await DotNetCrypto.GenerateAESGCMKey(sharedSecret);
            var origMsgBytes = await DotNetCrypto.Decrypt(encKey, args.EncryptedMessage);
            var origMsg = Encoding.UTF8.GetString(origMsgBytes);
            var responseMsg = "Response message!";
            var responseBytes = Encoding.UTF8.GetBytes(responseMsg);
            var encMsg = await DotNetCrypto.Encrypt(encKey, responseBytes);
            return encMsg;
        }

        // ==================== Cross-Platform Test Endpoints ====================

        /// <summary>
        /// Server signs data with DotNetCrypto ECDSA and returns the signature + public key
        /// </summary>
        [HttpPost("SignData")]
        public async Task<CrossPlatformSignResult> SignData([FromBody] byte[] data)
        {
            await InitAsync();
            var signature = await DotNetCrypto.Sign(ECDSAKey!, data, "SHA-512");
            var publicKey = await DotNetCrypto.ExportPublicKeySpki(ECDSAKey!);
            return new CrossPlatformSignResult { Signature = signature, PublicKeySpki = publicKey };
        }

        /// <summary>
        /// Server verifies a signature created by the browser
        /// </summary>
        [HttpPost("VerifySignature")]
        public async Task<bool> VerifySignature([FromBody] CrossPlatformVerifyArgs args)
        {
            await InitAsync();
            using var browserKey = await DotNetCrypto.ImportECDSAKey(args.PublicKeySpki);
            return await DotNetCrypto.Verify(browserKey, args.Data, args.Signature, "SHA-512");
        }

        /// <summary>
        /// Server hashes data with DotNetCrypto and returns the hash
        /// </summary>
        [HttpPost("Digest")]
        public async Task<byte[]> Digest([FromBody] CrossPlatformDigestArgs args)
        {
            return await DotNetCrypto.Digest(args.HashName, args.Data);
        }

        /// <summary>
        /// Server encrypts data with AES-GCM using provided key material
        /// </summary>
        [HttpPost("AesGcmEncrypt")]
        public async Task<byte[]> AesGcmEncrypt([FromBody] CrossPlatformAesGcmArgs args)
        {
            using var key = await DotNetCrypto.GenerateAESGCMKey(args.Secret);
            return await DotNetCrypto.Encrypt(key, args.Data);
        }

        /// <summary>
        /// Server decrypts data with AES-GCM using provided key material
        /// </summary>
        [HttpPost("AesGcmDecrypt")]
        public async Task<byte[]> AesGcmDecrypt([FromBody] CrossPlatformAesGcmArgs args)
        {
            using var key = await DotNetCrypto.GenerateAESGCMKey(args.Secret);
            return await DotNetCrypto.Decrypt(key, args.Data);
        }

        /// <summary>
        /// Server encrypts data with AES-CBC using provided raw key
        /// </summary>
        [HttpPost("AesCbcEncrypt")]
        public async Task<byte[]> AesCbcEncrypt([FromBody] CrossPlatformAesCbcArgs args)
        {
            using var key = await DotNetCrypto.ImportAESCBCKey(args.RawKey);
            return await DotNetCrypto.Encrypt(key, args.Data);
        }

        /// <summary>
        /// Server decrypts data with AES-CBC using provided raw key
        /// </summary>
        [HttpPost("AesCbcDecrypt")]
        public async Task<byte[]> AesCbcDecrypt([FromBody] CrossPlatformAesCbcArgs args)
        {
            using var key = await DotNetCrypto.ImportAESCBCKey(args.RawKey);
            return await DotNetCrypto.Decrypt(key, args.Data);
        }
    }

    // ==================== DTOs for Cross-Platform Tests ====================

    public class CrossPlatformSignResult
    {
        public byte[] Signature { get; set; } = Array.Empty<byte>();
        public byte[] PublicKeySpki { get; set; } = Array.Empty<byte>();
    }

    public class CrossPlatformVerifyArgs
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public byte[] Signature { get; set; } = Array.Empty<byte>();
        public byte[] PublicKeySpki { get; set; } = Array.Empty<byte>();
    }

    public class CrossPlatformDigestArgs
    {
        public string HashName { get; set; } = "SHA-256";
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }

    public class CrossPlatformAesGcmArgs
    {
        public byte[] Secret { get; set; } = Array.Empty<byte>();
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }

    public class CrossPlatformAesCbcArgs
    {
        public byte[] RawKey { get; set; } = Array.Empty<byte>();
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }
}
