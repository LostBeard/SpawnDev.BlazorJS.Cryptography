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
            var ret = "Hellow world!!";
            return new string[] { ret };
        }

        [HttpPost("GetSharedSecret")]
        public async Task<byte[]> GetSharedSecret(GetSharedSecretArgs args)
        {
            await InitAsync();
            // import the browser's base64 encoded ECDH public key
            using var browsersECDHKey = await DotNetCrypto.ImportECDHKey(Convert.FromBase64String(args.SenderECDHPublicKeyB64));
            // generate a shared secret
            // the browser will geenrate a secret that should be identical to the one the server creates
            var sharedSecret = await DotNetCrypto.DeriveBits(ECDHKey!, browsersECDHKey);
            // send it to the browser for comparison. you would never do this in production.
            return sharedSecret;
        }

        [HttpPost("EncryptionTest")]
        public async Task<byte[]> EncryptionTest(EncryptionTestArgs args)
        {
            await InitAsync();
            // import the browser's base64 encoded ECDH public key
            using var browsersECDHKey = await DotNetCrypto.ImportECDHKey(Convert.FromBase64String(args.SenderECDHPublicKeyB64));
            // generate a shared secret
            // the browser will generate a secret that should be identical to the one the server creates
            var sharedSecret = await DotNetCrypto.DeriveBits(ECDHKey!, browsersECDHKey);
            // create an encryption key based on the shared secret
            using var encKey = await DotNetCrypto.GenerateAESGCMKey(sharedSecret);
            // decrypt the message encrypted by the browser
            var origMsgBytes = await DotNetCrypto.Decrypt(encKey, args.EncryptedMessage);
            // convert the message to text
            var origMsg = Encoding.UTF8.GetString(origMsgBytes);
            // send an encryptd response
            var responseMsg = "Response message!";
            // convert bytes to text
            var responseBytes = Encoding.UTF8.GetBytes(responseMsg);
            // encrypt using the shared key
            var encMsg = await DotNetCrypto.Encrypt(encKey, responseBytes);
            // send it to the browser for comparison. you would never do this in production.
            return encMsg;
        }
    }
}
