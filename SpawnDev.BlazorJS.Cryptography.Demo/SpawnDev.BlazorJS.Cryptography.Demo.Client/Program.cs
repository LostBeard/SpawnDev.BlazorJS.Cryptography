using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.JSInterop;
using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

var temp = typeof(JSInProcessRuntime).GetMethod("Invoke", new Type[] { typeof(string), typeof(object[]) });

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Crypto for the browser
builder.Services.AddScoped<BrowserCrypto>();

// Crypto for the browser (wasm only. on wasm blazor it can be used as an alternative to BrowserCrypto)
builder.Services.AddScoped<BrowserWASMCrypto>();

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// build and start the app
var host = await builder.Build().StartBackgroundServices();

await host.BlazorJSRunAsync();
