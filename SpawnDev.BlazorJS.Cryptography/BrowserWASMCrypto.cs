#if NET6_0_OR_GREATER
using SpawnDev.BlazorJS.JSObjects;
using System.Runtime.Versioning;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Cross platform cryptography tools.<br/>
    /// BrowserWASMCrypto uses the web browser's SubtleCrypto API. Requires IJInProcessSRuntime and supports only webassembly rendering.<br/>
    /// </summary>
    public partial class BrowserWASMCrypto : PortableCrypto
    {
        BlazorJSRuntime JS { get; set; }
        Lazy<SubtleCrypto> _SubtleCrypto;
        SubtleCrypto SubtleCrypto => _SubtleCrypto.Value;
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="js"></param>
        [SupportedOSPlatform("browser")]
        public BrowserWASMCrypto(BlazorJSRuntime js)
        {
            JS = js;
            _SubtleCrypto = new Lazy<SubtleCrypto>(() => JS.Get<SubtleCrypto>("crypto.subtle"));
        }
    }
}
#endif
