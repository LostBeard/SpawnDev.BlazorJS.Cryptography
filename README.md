# SpawnDev.BlazorJS.Cryptography

[![NuGet](https://badge.fury.io/nu/SpawnDev.BlazorJS.Cryptography.svg?label=SpawnDev.BlazorJS.Cryptography)](https://www.nuget.org/packages/SpawnDev.BlazorJS.Cryptography)

A cross platform cryptography library that supports encryption with AES-GCM, shared secret generation with ECDH, data signatures with ECDSA, and hashing with SHA on Windows, Linux, and Browser (Blazor WebAssembly) platforms.

This project aims to simplify common cryptography tasks with an API that is consistent on .Net Web API servers and in the web browser with Blazor WebAssembly.

[PortableCrypto](#PortableCrypto) and the related classes wrap underlying cryptographic classes that are chosen based on the current platform. On Window and Linux, classes such as AesGcm, ECDiffieHellman, ECDsa, and SHA from Microsoft's System.Security.Cryptography library are used. When running under Blazor WebAssembly on the browser the browser [Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Crypto) and [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) APIs are used. By wrapping these underlying libraries we can provide a consistent and reliable API regardless of the executing platform.

### Getting started

Add the Nuget package
```nuget
dotnet add package SpawnDev.BlazorJS.Cryptography
```

Add PortableCrypto service and SpawnDev.BlazorJS dependency to Program.cs 
```cs

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Add PortableCrypto service
builder.Services.AddSingleton<PortableCrypto>();

```

Inject PortableCrypto
```cs
[Inject] PortableCrypto PortableCrypto { get; set; }
```

## PortableCrypto
- The PortableCrypto service provides an API that can be used on the server and on the browser to provide cross platform compatible cryptographic methods.

### PortableCrypto - SHA

#### `Task<byte[]> Digest(string hashName, byte[] data)`
- Hash the specified data using the specified hash algorithm

### PortableCrypto - ECDH

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

### PortableCrypto - ECDSA

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


