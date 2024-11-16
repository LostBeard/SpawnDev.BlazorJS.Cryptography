# SpawnDev.BlazorJS.Cryptography

[![NuGet](https://badge.fury.io/nu/SpawnDev.BlazorJS.Cryptography.svg?delta=9&label=SpawnDev.BlazorJS.Cryptography)](https://www.nuget.org/packages/SpawnDev.BlazorJS.Cryptography)

.Net cryptography library for Blazor, .Net Web APIs, and .Net apps. Supports browser and non-browser platforms.

### The problem this library solves
Most of Microsoft's System.Security.Cryptography library is marked `[UnsupportedOSPlatform("browser")]`. To work around this limitation, the browser's built in [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) API is used when running in the browser and Microsoft's System.Security.Cryptography libraries are used when running on non-browser platforms.

### Features
- AES-GCM - symmetric encryption and decryption
- ECDH - shared secret generation (enables asymmetric encryption)
- ECDSA - data signing and verification
- SHA - data hashing

### PortableCrypto Classes
The classes `DotNetCrypto`, `BrowserCrypto`, and `BrowserWASMCrypto` all inherit from [`PortableCrypto`](#portablecrypto-abstract-class) to provide a shared interface to common cryptography methods regardless of the platform the app is being executed on.
   
**DotNetCrypto**  
- Uses .Net System.Security.Cryptography on the executing platform
- Browser platform not supported
- Supports non-browser platforms (windows, linux, etc)
- Targets Blazor server, .Net Web APIs, any non-browser platform .Net Apps
  
**BrowserCrypto**
- Uses IJSRuntime to access the browser's [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) API
- Supports both server rendering and WebAssembly rendering modes
- Targets the browser platform via Blazor server or Blazor WebAssembly
  
**BrowserWASMCrypto**
- Uses IJInProcessSRuntime to access the browser's [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) API
- Supports only WebAssembly rendering
- Targets the browser via Blazor WebAssembly

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

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Crypto for the server. Uses System.Security.Cryptography.
builder.Services.AddSingleton<DotNetCrypto>();

// Crypto for the browser. Uses the browser's SubtleCrypto API via IJSRuntime.
// Used on server for server side rendering
builder.Services.AddScoped<BrowserCrypto>();
```

#### Blazor WebAssembly
WebAssembly Program.cs 
```cs
// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Crypto for the browser. Uses the browser's SubtleCrypto API.
// Used in Blazor WebAssembly for WebAssembly rendering
builder.Services.AddScoped<BrowserCrypto>();
```

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

## PortableCrypto Abstract Class

### SHA - Data Hashing

#### `Task<byte[]> Digest(string hashName, byte[] data)`
- Hash the specified data using the specified hash algorithm

### ECDH - Shared secret generation

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

### ECDSA - Data Signing

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

### AES-GCM - Data Encryption

#### `Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)`
- Generate an AES-GCM key using a secret byte array

#### `Task<PortableAESGCMKey> GenerateAESGCMKey(byte[] secret, byte[] salt, int iterations = 25000, string hashName = HashName.SHA256, int keySizeBytes = 32, int tagSizeBytes = 16, int nonceSizeBytes = 12, bool extractable = true)`
- Generate an AES-GCM key using a secret byte array and a salt

#### `Task<byte[]> Encrypt(PortableAESGCMKey key, byte[] plainBytes)`
- Encrypt data using an AES-GCM key

#### `Task<byte[]> Decrypt(PortableAESGCMKey key, byte[] encryptedData)`
- Decrypt data using an AES-GCM key