# SpawnDev.BlazorJS.Cryptography

[![NuGet](https://badge.fury.io/nu/SpawnDev.BlazorJS.Cryptography.svg?delta=9&label=SpawnDev.BlazorJS.Cryptography)](https://www.nuget.org/packages/SpawnDev.BlazorJS.Cryptography)

A .Net cryptography library that runs in Blazor WebAssembly apps and in .Net Web APIs.

### The problem this library solves
Microsoft's System.Security.Cryptography library does not work in Blazor WebAssembly. This library uses the browser's built in [Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Crypto) and [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) cryptography libraries when running in the browser and Microsoft's System.Security.Cryptography libraries when running on Windows and Linux.

### Features
- AES-GCM - symmetric encryption and decryption
- ECDH - shared secret generation (enables asymmetric encryption)
- ECDSA - data signing and verification
- SHA - data hashing

### Supported Platforms
- Browser (Blazor WebAssembly) - uses [Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Crypto) and [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
- Windows - uses System.Security.Cryptography
- Linux - uses System.Security.Cryptography

### Getting started

Add the Nuget package
```nuget
dotnet add package SpawnDev.BlazorJS.Cryptography
```

#### Web API Server Project
Web API Server Program.cs
```cs
// Crypto for the server. Uses System.Security.Cryptography.
builder.Services.AddSingleton<DotNetCrypto>();
```

#### Blazor Server Project
Blazor Server Program.cs
```cs
// Add BlazorJSRuntime service (pre-req)
builder.Services.AddBlazorJSRuntime();

// Crypto for the server. Uses System.Security.Cryptography.
builder.Services.AddSingleton<DotNetCrypto>();

// Crypto for the browser. Uses the browser's SubtleCrypto API.
// Used on server for server side rendering
builder.Services.AddScoped<BrowserCrypto>();
```

#### Blazor WebAssembly
WebAssembly Program.cs 
```cs
// Add BlazorJSRuntime service (pre-req)
builder.Services.AddBlazorJSRuntime();

// Crypto for the browser. Uses the browser's SubtleCrypto API.
// Used in Blazor WebAssembly for WebAssembly rendering
builder.Services.AddScoped<BrowserCrypto>();
```

Inject BrowserCrypto service into a component to access the Cryptography on the browser. Works with both server side and web assembly rendering.
```cs
[Inject] 
BrowserCrypto BrowserCrypto { get; set; }
```

## PortableCrypto
- The PortableCrypto services, `DotNetCrypto` and `BrowserCrypto` provide an API that can be used on the server and on the browser to provide cross platform compatible cryptographic methods.

### SHA Example
- The below example, taken from the demo project, runs in Blazor server side rendering to test SHA hashing using the DotNetCrypto on the server and BrowserCrypto using IJSRuntime to run on the client browser.
```cs
var data = new byte[] { 0, 1, 2 };
// - Server
// DotNetCrypto indicated by the appended D, executes on the server using Microsoft.Security.Cryptography
var hashD = await DotNetCrypto.Digest("SHA-512", data);

// - Browser
// BrowserCrypto indicated by the appended B, executes on the browser using Javascript's SubtleCrypto APIs
var hashB = await BrowserCrypto.Digest("SHA-512", data);

// verify the hashes match
if (!hashB.SequenceEqual(hashD))
{
    throw new Exception("Hash mismatch");
}
```

### ECDH Example
- The below example, taken from the demo project, runs in Blazor server side rendering to test ECDH using the DotNetCrypto on the server and BrowserCrypto using IJSRuntime to run on the client browser.
```cs
// - Server
// generate server ECDH key
var ecdhD = await DotNetCrypto.GenerateECDHKey();
// export ecdhD public key for browser to use
var ecdhDPublicKeyBytes = await DotNetCrypto.ExportPublicKeySpki(ecdhD);

// - Browser
// generate browser ECDH key
var ecdhB = await BrowserCrypto.GenerateECDHKey();
// export ecdhB public key for server to use
var ecdhBPublicKeyBytes = await BrowserCrypto.ExportPublicKeySpki(ecdhB);

// - Server
// import the browser's ECDH public key using DotNetCrypto so DotNetCrypto can work with it
var ecdhBPublicKeyD = await DotNetCrypto.ImportECDHKey(ecdhBPublicKeyBytes);
// create shared secret
var sharedSecretD = await DotNetCrypto.DeriveBits(ecdhD, ecdhBPublicKeyD);

// - Browser
// import the server's ECDH public key using BrowserCrypto so BrowserCrypto can work with it
var ecdhDPublicKeyB = await BrowserCrypto.ImportECDHKey(ecdhDPublicKeyBytes);
// create shared secret
var sharedSecretB = await BrowserCrypto.DeriveBits(ecdhB, ecdhDPublicKeyB);

// verify the shared secrets match
if (!sharedSecretB.SequenceEqual(sharedSecretD))
{
    throw new Exception("Shared secret mismatch");
}
```

## PortableCrypto API
### SHA

#### `Task<byte[]> Digest(string hashName, byte[] data)`
- Hash the specified data using the specified hash algorithm

### ECDH

#### `Task<PortableECDHKey> GenerateECDHKey(string namedCurve = NamedCurve.P521, bool extractable = true)`
- Generate a new ECDH crypto key

#### `Task<byte[]> ExportPublicKeySpki(PortableECDHKey key)`
- Export the ECDH public key in Spki format

#### `Task<byte[]> ExportPrivateKeyPkcs8(PortableECDHKey key)`
- Export the ECDH private key in Pkcs8 format

#### `Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, string namedCurve = NamedCurve.P521, bool extractable = true)`
- Import the ECDH public key

#### `Task<PortableECDHKey> ImportECDHKey(byte[] publicKeySpki, byte[] privateKeyPkcs8, string namedCurve = NamedCurve.P521, bool extractable = true)`
- Import the ECDH private key

#### `Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey, int bitLength)`
- Create a shared secret that is cross-platform compatible

#### `Task<byte[]> DeriveBits(PortableECDHKey localPartyKey, PortableECDHKey otherPartyKey)`
- Create a shared secret that is cross-platform compatible

### ECDSA

#### `Task<PortableECDSAKey> GenerateECDSAKey(string namedCurve = NamedCurve.P521, bool extractable = true)`
- Generate a new ECDSA key

#### `Task<byte[]> ExportPublicKeySpki(PortableECDSAKey key)`
- Exports the ECDSA public key in Spki format

#### `Task<byte[]> ExportPrivateKeyPkcs8(PortableECDSAKey key)`
- Exports the ECDSA private key in Pkcs8 format

#### `Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, string namedCurve = NamedCurve.P521, bool extractable = true)`
- Import an ECDSA public key

#### `Task<PortableECDSAKey> ImportECDSAKey(byte[] publicKeySpkiData, byte[] privateKeyPkcs8Data, string namedCurve = NamedCurve.P521, bool extractable = true)`
- Import an ECDSA public and private key

#### `Task<bool> Verify(PortableECDSAKey key, byte[] data, byte[] signature, string hashName = HashName.SHA512)`
- Verify a data signature

#### `Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string hashName = HashName.SHA512)`
- Sign data using an ECDSA key

### AES-GCM

#### `Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)`
- Generate an AES-GCM key using a secret byte array

#### `Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)`
- Generate an AES-GCM key using a secret byte array and a salt

#### `Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes)`
- Encrypt data using an AES-GCM key

#### `Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData)`
- Decrypt data using an AES-GCM key