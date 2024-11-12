# SpawnDev.BlazorJS.Cryptography

[![NuGet version](https://badge.fury.io/nu/SpawnDev.BlazorJS.Cryptography.svg?label=SpawnDev.BlazorJS.Cryptography)](https://www.nuget.org/packages/SpawnDev.BlazorJS.Cryptography)

A cross platform cryptography library that supports encryption with AES-GCM, shared secret generation with ECDH, data signatures with ECDSA, and hashing (SHA) on Windows, Linux, and Browser (Blazor WebAssembly) platforms.

This project aims to simplify common cryptography tasks with an API that is consistent on .Net Web API servers and in the web browser with Blazor WebAssembly.


### Getting started

#### Blazor WebAssembly
Example Program.cs 
```cs
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Add PortableCrypto service
builder.Services.AddSingleton<PortableCrypto>();

// build and start the app
await builder.Build().BlazorJSRunAsync();
```

Inject
```cs
[Inject] PortableCrypto PortableCrypto { get; set; }
```
