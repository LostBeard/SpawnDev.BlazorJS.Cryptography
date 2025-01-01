using SpawnDev.BlazorJS.Cryptography.DotNet;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
    {

        public override async Task<PortableAESCBCKey> GenerateAESCBCKey(int keySize, bool extractable = true)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = keySize;
            aes.GenerateKey();
            return new DotNetAESCBCKey(aes);
        }
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not DotNetAESCBCKey nKey) throw new NotImplementedException();
            if (padding == AESCBCPadding.None)
            {
                nKey.Key.Padding = PaddingMode.None;
            }
            else
            {
                nKey.Key.Padding = PaddingMode.PKCS7;
            }
            using var encryptor = nKey.Key.CreateEncryptor(nKey.Key.Key, iv);
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var swEncrypt = new BinaryWriter(csEncrypt);
            swEncrypt.Write(plainBytes);
            csEncrypt.FlushFinalBlock();
            msEncrypt.Position = 0;
            var encryptedData = msEncrypt.ToArray();
            if (!prependIV) return Task.FromResult(encryptedData);
            var encryptedDataLength = encryptedData.Length + iv.Length;
            var result = new byte[encryptedDataLength];
            // + iv
            iv.CopyTo(result, 0);
            // + encrypted data
            encryptedData.CopyTo(result, iv.Length);
            return Task.FromResult(result);
        }
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            var iv = RandomBytes(16);
            return Encrypt(key, plainBytes, iv, prependIV, padding);
        }
        public override Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not DotNetAESCBCKey nKey) throw new NotImplementedException();
            if (padding == AESCBCPadding.None)
            {
                nKey.Key.Padding = PaddingMode.None;
            }
            else
            {
                nKey.Key.Padding = PaddingMode.PKCS7;
            }
            using var decryptor = nKey.Key.CreateDecryptor(nKey.Key.Key, iv);
            using var msDecrypt = new MemoryStream();
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write);
            using var srDecrypt = new BinaryWriter(csDecrypt);
            srDecrypt.Write(encryptedData);
            var remainder = encryptedData.Length % nKey.Key.BlockSize;

            csDecrypt.FlushFinalBlock();
            msDecrypt.Position = 0;
            var data = msDecrypt.ToArray();
            return Task.FromResult(data);
        }
        public override Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            var iv = new byte[16];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
            var encrypted = new byte[encryptedData.Length - 16];
            Buffer.BlockCopy(encryptedData, 16, encrypted, 0, encrypted.Length);
            return Decrypt(key, encrypted, iv, padding);
        }
        public override async Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true)
        {
            var key = Aes.Create();
            key.Key = rawKey;
            key.Padding = PaddingMode.PKCS7;
            key.Mode = CipherMode.CBC;
            return new DotNetAESCBCKey(key);
        }
        public override async Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key)
        {
            if (key is not DotNetAESCBCKey nKey) throw new NotImplementedException();
            return nKey.Key.Key;
        }
    }
}
