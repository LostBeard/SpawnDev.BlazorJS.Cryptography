using SpawnDev.BlazorJS.JSObjects;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class PortableCrypto
    {
        /// <summary>
        /// Generate an AES-GCM key using a secret byte array
        /// </summary>
        /// <param name="secret">The secret that will be used to generate the key<br/>The salt will be taken from the end of the secret</param>
        /// <param name="iterations">
        /// A Number representing the number of times the hash function will be executed during key creation. This determines how computationally expensive (that is, slow) the key creation operation will be. In this context, slow is good, since it makes it more expensive for an attacker to run a dictionary attack against the keys. The general guidance here is to use as many iterations as possible, subject to keeping an acceptable level of performance for your application.
        /// </param>
        /// <param name="hashName">
        /// A string representing the digest algorithm to use. This may be one of:<br/>
        /// SHA-256<br/>
        /// SHA-384<br/>
        /// SHA-512
        /// </param>
        /// <param name="keySizeBytes">The length in bits of the key to generate. This must be one of: 16, 24, or 32 (128, 192, or 256 bits).</param>
        /// <param name="tagSizeBytes">The size of the tag, in bytes, that encryption and decryption must use.</param>
        /// <param name="nonceSizeBytes">The size of the nonce, in bytes, that encryption and decryption must use.</param>
        /// <param name="extractable">A boolean value indicating whether it will be possible to export the key (Browser environment only)</param>
        /// <returns>PortableAESGCMKey</returns>
        /// <exception cref="Exception"></exception>
        public Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)
        {
            if (secret.Length < keySizeBytes * 2) throw new Exception($"{nameof(secret)}.Length must be at least {nameof(keySizeBytes)} * 2");
            var salt = secret[^keySizeBytes..];
            secret = secret[..keySizeBytes];
            return GenerateAESGCMKey(secret, salt, iterations, hashName, keySizeBytes, tagSizeBytes, nonceSizeBytes, extractable);
        }
        /// <summary>
        /// Generate an AES-GCM key using a secret byte array and a salt
        /// </summary>
        /// <param name="secret">The secret that will be used to generate the key</param>
        /// <param name="salt">This should be a random or pseudo-random value of at least 16 bytes</param>
        /// <param name="iterations">
        /// A Number representing the number of times the hash function will be executed during key creation. This determines how computationally expensive (that is, slow) the key creation operation will be. In this context, slow is good, since it makes it more expensive for an attacker to run a dictionary attack against the keys. The general guidance here is to use as many iterations as possible, subject to keeping an acceptable level of performance for your application.
        /// </param>
        /// <param name="hashName">
        /// A string representing the digest algorithm to use. This may be one of:<br/>
        /// SHA-256<br/>
        /// SHA-384<br/>
        /// SHA-512
        /// </param>
        /// <param name="keySizeBytes">The length in bits of the key to generate. This must be one of: 16, 24, or 32 (128, 192, or 256 bits).</param>
        /// <param name="tagSizeBytes">The size of the tag, in bytes, that encryption and decryption must use.</param>
        /// <param name="nonceSizeBytes">The size of the nonce, in bytes, that encryption and decryption must use.</param>
        /// <param name="extractable">A boolean value indicating whether it will be possible to export the key (a value of false is supported in the Browser environment only)</param>
        /// <returns>PortableAESGCMKey</returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)
        {
            var algorithmName = "AES-GCM";
            if (OperatingSystem.IsBrowser())
            {
                var keyUsages = new string[] { "encrypt", "decrypt" };
                var pbkKey = await SubtleCrypto!.ImportKey("raw", secret, "PBKDF2", false, new string[] { "deriveKey" });
                var key = await SubtleCrypto!.DeriveKey(
                    new Pbkdf2Params
                    {
                        Hash = hashName,
                        Iterations = iterations,
                        Salt = salt,
                    },
                    pbkKey,
                    new AesKeyGenParams
                    {
                        Name = algorithmName,
                        Length = keySizeBytes * 8,
                    },
                    extractable,
                    keyUsages
                );
                return new PortableAESGCMKeyJS(key, nonceSizeBytes, tagSizeBytes);
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var hashAlgorithm = HashNameToHashAlgorithmName(hashName);
                // get encrypted message and decrypt using shared secret
                using var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, iterations, hashAlgorithm);
                var key = new AesGcm(pbkdf2.GetBytes(keySizeBytes), tagSizeBytes);
                return new PortableAESGCMKeyNet(key, nonceSizeBytes);
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Encrypt data using an AES-GCM key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes)
        {
            var tagSize = key.TagSizeBytes;
            var nonceSize = key.NonceSizeBytes;
            int cipherDataSize = plainBytes.Length;
            int encryptedDataLength = 8 + nonceSize + cipherDataSize + tagSize;
            var nonce = RandomBytes(nonceSize);
            if (OperatingSystem.IsBrowser())
            {
                var jsKey = key as PortableAESGCMKeyJS;
                using var ret = await SubtleCrypto!.Encrypt(new AesGcmParams { Iv = nonce, TagLength = tagSize * 8 }, jsKey!.Key, plainBytes);
                var cipherDataAndTag = ret.ReadBytes();
                // SubtleCrypto, unlike .Net, appends the tag data to the cipherData
                // encryptedData = nonceSize + nonce + tagSize + cipherDataAndTag
                var encryptedData = new byte[encryptedDataLength];
                // + nonceSize
                BinaryPrimitives.WriteInt32LittleEndian(new Span<byte>(encryptedData, 0, 4), nonceSize);
                // + nonce
                nonce.CopyTo(encryptedData, 4);
                // + tagSize
                BinaryPrimitives.WriteInt32LittleEndian(new Span<byte>(encryptedData, (4 + nonceSize), 4), tagSize);
                // + cipherDataAndTag
                cipherDataAndTag.CopyTo(encryptedData, 8 + nonceSize);
                return encryptedData;
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                var netKey = key as PortableAESGCMKeyNet;
                var cipherData = new byte[cipherDataSize];
                var tag = new byte[tagSize];
                netKey!.Key.Encrypt(nonce, plainBytes, cipherData, tag);
                // .Net, unlike SubtleCrypto, does not append the tag data to the cipherData
                // encryptedData = nonceSize + nonce + tagSize + cipherData + tag
                var encryptedData = new byte[encryptedDataLength];
                // + nonceSize
                BinaryPrimitives.WriteInt32LittleEndian(new Span<byte>(encryptedData, 0, 4), nonceSize);
                // + nonce
                nonce.CopyTo(encryptedData, 4);
                // + tagSize
                BinaryPrimitives.WriteInt32LittleEndian(new Span<byte>(encryptedData, (4 + nonceSize), 4), tagSize);
                // + cipherData
                cipherData.CopyTo(encryptedData, 8 + nonceSize);
                // + tag
                tag.CopyTo(encryptedData, 4 + nonceSize + 4 + cipherDataSize);
                return encryptedData;
            }
            throw new NotImplementedException();
        }
        /// <summary>
        /// Decrypt data using an AES-GCM key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData)
        {
            // encryptedData = nonceSize + nonce + tagSize + cipherData + tag
            // get nonceSize
            var nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData);
            // get nonce
            var nonce = new byte[nonceSize];
            Buffer.BlockCopy(encryptedData, 4, nonce, 0, nonceSize);
            // get tagSize
            var tagSizeBytes = encryptedData[(4 + nonceSize)..(8 + nonceSize)];
            var tagSize = BinaryPrimitives.ReadInt32LittleEndian(tagSizeBytes);
            if (OperatingSystem.IsBrowser())
            {
                // get cipherDataAndTag
                var cipherDataAndTagSize = encryptedData.Length - (8 + nonceSize);
                var cipherDataAndTag = new byte[cipherDataAndTagSize];
                Buffer.BlockCopy(encryptedData, 8 + nonceSize, cipherDataAndTag, 0, cipherDataAndTagSize);
                // decrypt
                var jsKey = key as PortableAESGCMKeyJS;
                var ret = await SubtleCrypto!.Decrypt(new AesGcmParams { Iv = nonce, TagLength = tagSize * 8 }, jsKey!.Key, cipherDataAndTag);
                return ret.ReadBytes();
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            {
                // get cipherData
                var cipherDataSize = encryptedData.Length - (8 + nonceSize + tagSize);
                var cipherData = new byte[cipherDataSize];
                Buffer.BlockCopy(encryptedData, 8 + nonceSize, cipherData, 0, cipherDataSize);
                // get tag
                var tag = new byte[tagSize];
                Buffer.BlockCopy(encryptedData, 8 + nonceSize + cipherDataSize, tag, 0, tagSize);
                // decrypt
                var plaintext = new byte[cipherDataSize];
                var netKey = key as PortableAESGCMKeyNet;
                netKey!.Key.Decrypt(nonce, cipherData, tag, plaintext);
                return plaintext;
            }
            throw new NotImplementedException();
        }
    }
}
