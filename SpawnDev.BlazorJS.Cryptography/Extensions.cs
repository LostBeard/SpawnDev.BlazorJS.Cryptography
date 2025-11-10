using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// Extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Adds the IPortableCrypto service singleton based on the running platform.<br/>
        /// If running in the browser, BrowserWASMCrypto is used,<br/>
        /// otherwise DotNetCrypto is used.<br/>
        /// NOTE: Use BrowserCrypto directly if you need client side crypto with ServerSide rendering.
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        public static IServiceCollection AddPlatformCrypto(this IServiceCollection services)
        {
            if (OperatingSystem.IsBrowser())
            {
                services.TryAddSingleton<IPortableCrypto, BrowserWASMCrypto>();
            }
            else
            {
                services.TryAddSingleton<IPortableCrypto, DotNetCrypto>();
            }
            return services;
        }
    }
}
