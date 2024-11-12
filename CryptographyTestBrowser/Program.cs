using CryptographyTestBrowser;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SpawnDev.BlazorJS.Cryptography;
using SpawnDev.BlazorJS;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Add PortableCrypto service
builder.Services.AddSingleton<PortableCrypto>();

// build and start the app
await builder.Build().BlazorJSRunAsync();
