using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Runtime.InteropServices;
using System.Text;
using static SpawnDev.BlazorJS.Cryptography.Demo.Client.Pages.TestPage;

namespace SpawnDev.BlazorJS.Cryptography.Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CryptographyTestController : ControllerBase
    {

        PortableCrypto PortableCrypto;
        public CryptographyTestController(PortableCrypto portableCrypto)
        {
            PortableCrypto = portableCrypto;
            
        }
        static bool BeenInit = false;
        static PortableECDSAKey? ECDSAKey = null;
        static PortableECDHKey? ECDHKey = null;
        async Task InitAsync()
        {
            if (BeenInit) return;
            BeenInit = true;
            ECDSAKey = await PortableCrypto.GenerateECDSAKey();
            ECDHKey = await PortableCrypto.GenerateECDHKey();
        }

        [HttpGet("ecdsa")]
        public async Task<byte[]> GetECDSA()
        {
            await InitAsync();
            var publicKeyBytes = await PortableCrypto.ExportPublicKeySpki(ECDSAKey!);
            return publicKeyBytes;
        }

        [HttpGet("ecdh")]
        public async Task<byte[]> GetECDH()
        {
            await InitAsync();
            var publicKeyBytes = await PortableCrypto.ExportPublicKeySpki(ECDHKey!);
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
            using var browsersECDHKey = await PortableCrypto.ImportECDHKey(Convert.FromBase64String(args.SenderECDHPublicKeyB64));
            // generate a shared secret
            // the browser will geenrate a secret that should be identical to the one the server creates
            var sharedSecret = await PortableCrypto.DeriveBits(ECDHKey!, browsersECDHKey);
            // send it to the browser for comparison. you would never do this in production.
            return sharedSecret;
        }

        [HttpPost("EncryptionTest")]
        public async Task<byte[]> EncryptionTest(EncryptionTestArgs args)
        {
            await InitAsync();
            // import the browser's base64 encoded ECDH public key
            using var browsersECDHKey = await PortableCrypto.ImportECDHKey(Convert.FromBase64String(args.SenderECDHPublicKeyB64));
            // generate a shared secret
            // the browser will generate a secret that should be identical to the one the server creates
            var sharedSecret = await PortableCrypto.DeriveBits(ECDHKey!, browsersECDHKey);
            // create an encryption key based on the shared secret
            using var encKey = await PortableCrypto.GenerateAESGCMKey(sharedSecret);
            // decrypt the message encrypted by the browser
            var origMsgBytes = await PortableCrypto.Decrypt(encKey, args.EncryptedMessage);
            // convert the message to text
            var origMsg = Encoding.UTF8.GetString(origMsgBytes);
            // send an encryptd response
            var responseMsg = "Response message!";
            // convert bytes to text
            var responseBytes = Encoding.UTF8.GetBytes(responseMsg);
            // encrypt using the shared key
            var encMsg = await PortableCrypto.Encrypt(encKey, responseBytes);
            // send it to the browser for comparison. you would never do this in production.
            return encMsg;
        }
    }
}
