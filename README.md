# SpawnDev.BlazorJS.Cryptography

[![NuGet](https://badge.fury.io/nu/SpawnDev.BlazorJS.Cryptography.svg?delta=9&label=SpawnDev.BlazorJS.Cryptography)](https://www.nuget.org/packages/SpawnDev.BlazorJS.Cryptography)

A .Net cryptography library that runs in Blazor WebAssembly apps and in .Net Web APIs.

### The problem this library solves
Microsoft's System.Security.Cryptography library does not work in Blazor WebAssembly. This library uses the browser's built in cryptography libraries [Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Crypto) and [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) when running on the browser and Microsoft's System.Security.Cryptography libraries when running on Windows and Linux.

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

Add PortableCrypto service and SpawnDev.BlazorJS dependency to Program.cs 
```cs
// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Add PortableCrypto service
builder.Services.AddSingleton<PortableCrypto>();
```

Inject PortableCrypto service into a component
```cs
[Inject] 
PortableCrypto PortableCrypto { get; set; }
```

## PortableCrypto
- The PortableCrypto service provides an API that can be used on the server and on the browser to provide cross platform compatible cryptographic methods.

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