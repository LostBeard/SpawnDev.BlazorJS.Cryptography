
using SpawnDev.BlazorJS.RemoteJSRuntime;
using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Cross platform cryptography tools.<br/>
    /// BrowserCrypto uses the web browser's SubtleCrypto API. Requires IJSRuntime and supports both server side rendering and webassembly rendering.<br/>
    /// </summary>
    public partial class BrowserCrypto : PortableCrypto
    {
        protected BlazorJSRuntimeAsync JSA { get; set; }
        SubtleCryptoAsync SubtleCrypto;
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="jsa"></param>
        public BrowserCrypto(BlazorJSRuntimeAsync jsa)
        {
            JSA = jsa;
            SubtleCrypto = new SubtleCryptoAsync(JSA);
        }
        Task<byte[]> ArrayBufferToBytes(ArrayBufferAsync arrayBuffer) => JSA.NewAsync<byte[]>("Uint8Array", arrayBuffer);
        async Task<ArrayBufferAsync> ArrayBufferFromBytes(byte[] data)
        {
            await using var uint8Array = await JSA.ReturnAs<Uint8ArrayAsync>(data);
            var arrayBuffer = await uint8Array.Get_Buffer();
            return arrayBuffer;
        }
    }
}
