using SpawnDev.BlazorJS.Cryptography.DotNet;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    public partial class DotNetCrypto
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
        public override Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)
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
        public override async Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)
        {
            var hashAlgorithm = HashNameToHashAlgorithmName(hashName);
            // get encrypted message and decrypt using shared secret
            using var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, iterations, hashAlgorithm);
            var key = new AesGcm(pbkdf2.GetBytes(keySizeBytes), tagSizeBytes);
            return new DotNetAESGCMKey(key, nonceSizeBytes);
        }
        /// <summary>
        /// Encrypt data using an AES-GCM key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plainBytes"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes)
        {
            if (key is not DotNetAESGCMKey keyNet) throw new NotImplementedException();
            var tagSize = key.TagSizeBytes;
            var nonceSize = key.NonceSizeBytes;
            int cipherDataSize = plainBytes.Length;
            int encryptedDataLength = 8 + nonceSize + cipherDataSize + tagSize;
            var nonce = RandomBytes(nonceSize);
            //
            var cipherData = new byte[cipherDataSize];
            var tag = new byte[tagSize];
            keyNet!.Key.Encrypt(nonce, plainBytes, cipherData, tag);
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
        /// <summary>
        /// Decrypt data using an AES-GCM key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData)
        {
            if (key is not DotNetAESGCMKey keyNet) throw new NotImplementedException();
            // encryptedData = nonceSize + nonce + tagSize + cipherData + tag
            // get nonceSize
            var nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData);
            // get nonce
            var nonce = new byte[nonceSize];
            Buffer.BlockCopy(encryptedData, 4, nonce, 0, nonceSize);
            // get tagSize
            var tagSizeBytes = encryptedData[(4 + nonceSize)..(8 + nonceSize)];
            var tagSize = BinaryPrimitives.ReadInt32LittleEndian(tagSizeBytes);
            //
            // get cipherData
            var cipherDataSize = encryptedData.Length - (8 + nonceSize + tagSize);
            var cipherData = new byte[cipherDataSize];
            Buffer.BlockCopy(encryptedData, 8 + nonceSize, cipherData, 0, cipherDataSize);
            // get tag
            var tag = new byte[tagSize];
            Buffer.BlockCopy(encryptedData, 8 + nonceSize + cipherDataSize, tag, 0, tagSize);
            // decrypt
            var plaintext = new byte[cipherDataSize];
            keyNet!.Key.Decrypt(nonce, cipherData, tag, plaintext);
            return plaintext;
        }
    }
}
