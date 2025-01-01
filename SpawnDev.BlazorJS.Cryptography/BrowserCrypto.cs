using Microsoft.JSInterop;
using SpawnDev.BlazorJS.RemoteJSRuntime.AsyncObjects;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Cross platform cryptography tools.<br/>
    /// BrowserCrypto uses the web browser's SubtleCrypto API. Requires IJSRuntime and supports both server side rendering and webassembly rendering.<br/>
    /// </summary>
    public partial class BrowserCrypto : PortableCrypto
    {
        /// <summary>
        /// The JS runtime
        /// </summary>
        protected IJSRuntime JSA { get; set; }
        SubtleCryptoAsync SubtleCrypto { get; }
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="jsa"></param>
        public BrowserCrypto(IJSRuntime jsa)
        {
            JSA = jsa;
            SubtleCrypto = new SubtleCryptoAsync(JSA);
        }
    }
}
