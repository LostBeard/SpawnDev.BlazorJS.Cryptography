using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Add PortableCrypto service
builder.Services.AddSingleton<PortableCrypto>();

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// build and start the app
await builder.Build().BlazorJSRunAsync();