using SpawnDev.BlazorJS.Cryptography.DotNet;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
    {
        /// <summary>
        /// Generate an AES-CBC key
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override Task<PortableAESCBCKey> GenerateAESCBCKey(int keySize, bool extractable = true)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = keySize;
            aes.GenerateKey();
            return Task.FromResult<PortableAESCBCKey>(new DotNetAESCBCKey(aes));
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <param name="iv"></param>
        /// <param name="prependIV"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, byte[] iv, bool prependIV = false, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not DotNetAESCBCKey nKey) throw new NotImplementedException();
            if (padding == AESCBCPadding.None)
            {
                if (plainBytes.Length % AES_CBC_BLOCK_SIZE != 0)
                {
                    throw new Exception($"{plainBytes} length must be a multiple of 16 when using no padding.");
                }
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
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <param name="prependIV"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public override Task<byte[]> Encrypt(PortableAESCBCKey key, byte[] plainBytes, bool prependIV = true, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            var iv = RandomBytes(16);
            return Encrypt(key, plainBytes, iv, prependIV, padding);
        }
        /// <summary>
        /// Encrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <param name="iv"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, byte[] iv, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            if (key is not DotNetAESCBCKey nKey) throw new NotImplementedException();
            if (padding == AESCBCPadding.None)
            {
                nKey.Key.Padding = PaddingMode.None;
                if (encryptedData.Length % AES_CBC_BLOCK_SIZE != 0)
                {
                    throw new Exception($"{encryptedData} length must be a multiple of 16 when using no padding.");
                }
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
            csDecrypt.FlushFinalBlock();
            msDecrypt.Position = 0;
            var data = msDecrypt.ToArray();
            return data;
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public override Task<byte[]> Decrypt(PortableAESCBCKey key, byte[] encryptedData, AESCBCPadding padding = AESCBCPadding.PKCS7)
        {
            var iv = new byte[16];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
            var encrypted = new byte[encryptedData.Length - 16];
            Buffer.BlockCopy(encryptedData, 16, encrypted, 0, encrypted.Length);
            return Decrypt(key, encrypted, iv, padding);
        }
        /// <summary>
        /// Decrypt data using an AES-CBC key
        /// </summary>
        /// <param name="rawKey"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public override Task<PortableAESCBCKey> ImportAESCBCKey(byte[] rawKey, bool extractable = true)
        {
            var key = Aes.Create();
            key.Key = rawKey;
            key.Padding = PaddingMode.PKCS7;
            key.Mode = CipherMode.CBC;
            return Task.FromResult<PortableAESCBCKey>(new DotNetAESCBCKey(key));
        }
        /// <summary>
        /// Export an AES-CBC key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task<byte[]> ExportAESCBCKey(PortableAESCBCKey key)
        {
            if (key is not DotNetAESCBCKey nKey) throw new NotImplementedException();
            return Task.FromResult(nKey.Key.Key);
        }
    }
}
