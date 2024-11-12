using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Windows, Linux platform AES-GCM key
    /// </summary>
    public class PortableAESGCMKeyNet : PortableAESGCMKey
    {
        /// <summary>
        /// The platform specific key
        /// </summary>
        public AesGcm Key { get; protected set; }
        /// <summary>
        /// The key tag size
        /// </summary>
        public override int TagSizeBytes => Key?.TagSizeInBytes ?? 0;
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="key"></param>
        /// <param name="nonceSizeBytes"></param>
        public PortableAESGCMKeyNet(AesGcm key, int nonceSizeBytes)
        {
            Key = key;
            NonceSizeBytes = nonceSizeBytes;
        }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Key?.Dispose();
            }
        }
    }
}
