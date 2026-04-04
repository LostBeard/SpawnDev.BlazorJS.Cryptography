using System.Numerics;
using System.Security.Cryptography;

namespace SpawnDev.BlazorJS.Cryptography.DotNet;

/// <summary>
/// Pure managed C# implementation of Ed25519 (RFC 8032).
/// Zero external dependencies. Uses BigInteger with extended projective coordinates.
/// Verified against RFC 8032 test vectors.
/// </summary>
internal static class Ed25519Managed
{
    /// <summary>Field prime p = 2^255 - 19</summary>
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;

    /// <summary>Group order l = 2^252 + 27742317777372353535851937790883648493</summary>
    private static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    /// <summary>Curve parameter d = -121665 / 121666 mod p</summary>
    private static readonly BigInteger D;

    /// <summary>sqrt(-1) mod p = 2^((p-1)/4) mod p</summary>
    private static readonly BigInteger SqrtM1;

    /// <summary>Base point in extended projective coordinates</summary>
    private static readonly ExtPoint BasePoint;

    // ASN.1 DER prefixes — fixed because Ed25519 keys are always 32 bytes
    // SPKI: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused) { 32 bytes } }
    private static readonly byte[] SpkiPrefix = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00 };
    // PKCS8: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { 32 bytes } } }
    private static readonly byte[] Pkcs8Prefix = { 0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };

    static Ed25519Managed()
    {
        D = FMod(-121665 * BigInteger.ModPow(121666, P - 2, P));
        SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
        // Base point: y = 4/5 mod p, x = positive (even) root
        var by = FMod(4 * BigInteger.ModPow(5, P - 2, P));
        var bx = RecoverX(by);
        if (!bx.IsEven) bx = P - bx;
        BasePoint = new ExtPoint(bx, by, BigInteger.One, FMod(bx * by));
    }

    #region Modular Arithmetic

    /// <summary>Positive mod p</summary>
    private static BigInteger FMod(BigInteger a)
    {
        var r = a % P;
        return r.Sign < 0 ? r + P : r;
    }

    /// <summary>Positive mod m</summary>
    private static BigInteger Mod(BigInteger a, BigInteger m)
    {
        var r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    /// <summary>Recover x from y coordinate. Returns non-negative x.</summary>
    private static BigInteger RecoverX(BigInteger y)
    {
        // x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
        var y2 = y * y % P;
        var u = FMod(y2 - 1);
        var v = FMod(D * y2 % P + 1);
        // x = u * v^3 * (u * v^7)^((p-5)/8) mod p
        var v3 = BigInteger.ModPow(v, 3, P);
        var v7 = BigInteger.ModPow(v, 7, P);
        var x = FMod(u * v3 % P * BigInteger.ModPow(FMod(u * v7), (P - 5) / 8, P));
        // Verify: v * x^2 should equal u mod p
        if (FMod(v * x % P * x) != u)
        {
            x = FMod(x * SqrtM1);
            if (FMod(v * x % P * x) != u)
                throw new CryptographicException("Invalid Ed25519 point encoding");
        }
        return x;
    }

    #endregion

    #region Extended Projective Point Operations

    /// <summary>Point in extended projective coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, x*y=T/Z</summary>
    private readonly struct ExtPoint
    {
        public readonly BigInteger X, Y, Z, T;
        public ExtPoint(BigInteger x, BigInteger y, BigInteger z, BigInteger t) { X = x; Y = y; Z = z; T = t; }
        public static readonly ExtPoint Identity = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
    }

    /// <summary>Point doubling (dbl-2008-hwcd). Curve: -x^2+y^2=1+d*x^2*y^2 (a=-1)</summary>
    private static ExtPoint Double(in ExtPoint p)
    {
        var a = p.X * p.X % P;
        var b = p.Y * p.Y % P;
        var c = 2 * p.Z * p.Z % P;
        var d = FMod(-a);         // a_coeff * A, where a_coeff = -1
        var e = FMod((p.X + p.Y) * (p.X + p.Y) % P - a - b);
        var g = FMod(d + b);
        var f = FMod(g - c);
        var h = FMod(d - b);
        return new ExtPoint(e * f % P, g * h % P, f * g % P, e * h % P);
    }

    /// <summary>Point addition (add-2008-hwcd). Curve: -x^2+y^2=1+d*x^2*y^2 (a=-1)</summary>
    private static ExtPoint Add(in ExtPoint p1, in ExtPoint p2)
    {
        var a = p1.X * p2.X % P;
        var b = p1.Y * p2.Y % P;
        var c = p1.T * D % P * p2.T % P;
        var dd = p1.Z * p2.Z % P;
        var e = FMod((p1.X + p1.Y) * (p2.X + p2.Y) % P - a - b);
        var f = FMod(dd - c);
        var g = FMod(dd + c);
        var h = FMod(b + a);     // B - a_coeff*A = B + A since a_coeff = -1
        return new ExtPoint(e * f % P, g * h % P, f * g % P, e * h % P);
    }

    /// <summary>Scalar multiplication using double-and-add (left-to-right binary)</summary>
    private static ExtPoint ScalarMul(in ExtPoint point, BigInteger scalar)
    {
        if (scalar.IsZero) return ExtPoint.Identity;
        var result = ExtPoint.Identity;
        var temp = point;
        while (scalar > 0)
        {
            if (!scalar.IsEven)
                result = Add(in result, in temp);
            temp = Double(in temp);
            scalar >>= 1;
        }
        return result;
    }

    #endregion

    #region Point Encoding / Decoding (RFC 8032 Section 5.1.2)

    /// <summary>Encode point as 32 bytes: y (little-endian 255 bits) + sign of x (bit 255)</summary>
    private static byte[] EncodePoint(in ExtPoint p)
    {
        var zinv = BigInteger.ModPow(p.Z, P - 2, P);
        var x = FMod(p.X * zinv);
        var y = FMod(p.Y * zinv);
        var result = new byte[32];
        var yBytes = y.ToByteArray(isUnsigned: true, isBigEndian: false);
        yBytes.AsSpan(0, Math.Min(yBytes.Length, 32)).CopyTo(result);
        if (!x.IsEven) result[31] |= 0x80;
        return result;
    }

    /// <summary>Decode 32-byte encoded point back to extended projective coordinates</summary>
    private static ExtPoint DecodePoint(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != 32)
            throw new CryptographicException("Ed25519 point must be 32 bytes");
        var buf = new byte[32];
        encoded.CopyTo(buf);
        bool xSign = (buf[31] & 0x80) != 0;
        buf[31] &= 0x7F;
        var y = new BigInteger(buf, isUnsigned: true, isBigEndian: false);
        if (y >= P) throw new CryptographicException("Ed25519 point y >= p");
        var x = RecoverX(y);
        if (x.IsEven == xSign) // xSign means x is odd
            x = FMod(P - x);
        return new ExtPoint(x, y, BigInteger.One, FMod(x * y));
    }

    #endregion

    #region SHA-512 Helper

    private static byte[] Sha512(params byte[][] parts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        foreach (var part in parts)
            hash.AppendData(part);
        return hash.GetHashAndReset();
    }

    #endregion

    #region Public API — Key Generation, Sign, Verify

    /// <summary>Generate a new Ed25519 key pair</summary>
    /// <returns>(publicKey: 32 bytes, seed: 32 bytes)</returns>
    public static (byte[] publicKey, byte[] seed) GenerateKeyPair()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var publicKey = GetPublicKey(seed);
        return (publicKey, seed);
    }

    /// <summary>Derive the 32-byte public key from a 32-byte seed</summary>
    public static byte[] GetPublicKey(byte[] seed)
    {
        var h = SHA512.HashData(seed);
        ClampScalar(h);
        var a = new BigInteger(h.AsSpan(0, 32), isUnsigned: true, isBigEndian: false);
        return EncodePoint(ScalarMul(in BasePoint, a));
    }

    /// <summary>Sign a message using a 32-byte seed (RFC 8032 Section 5.1.6)</summary>
    public static byte[] Sign(byte[] seed, byte[] message)
    {
        // 1. Expand seed
        var h = SHA512.HashData(seed);
        ClampScalar(h);
        var a = new BigInteger(h.AsSpan(0, 32), isUnsigned: true, isBigEndian: false);
        var publicKey = EncodePoint(ScalarMul(in BasePoint, a));

        // 2. Deterministic nonce: r = SHA-512(prefix || message) mod l
        var r = Mod(new BigInteger(Sha512(h[32..], message), isUnsigned: true, isBigEndian: false), L);

        // 3. R = [r]B
        var rBytes = EncodePoint(ScalarMul(in BasePoint, r));

        // 4. k = SHA-512(R || A || message) mod l
        var k = Mod(new BigInteger(Sha512(rBytes, publicKey, message), isUnsigned: true, isBigEndian: false), L);

        // 5. S = (r + k * a) mod l
        var S = Mod(r + k * a, L);
        var sBytes = S.ToByteArray(isUnsigned: true, isBigEndian: false);

        // 6. Signature = R (32) || S (32)
        var signature = new byte[64];
        rBytes.CopyTo(signature.AsSpan());
        sBytes.AsSpan(0, Math.Min(sBytes.Length, 32)).CopyTo(signature.AsSpan(32));
        return signature;
    }

    /// <summary>Verify an Ed25519 signature (RFC 8032 Section 5.1.7)</summary>
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (signature.Length != 64 || publicKey.Length != 32) return false;
        try
        {
            var R = DecodePoint(signature.AsSpan(0, 32));
            var A = DecodePoint(publicKey);
            var S = new BigInteger(signature.AsSpan(32, 32), isUnsigned: true, isBigEndian: false);
            if (S >= L) return false;

            // k = SHA-512(R || A || message) mod l
            var k = Mod(new BigInteger(Sha512(signature[..32], publicKey, message), isUnsigned: true, isBigEndian: false), L);

            // Check: [S]B == R + [k]A
            var lhs = ScalarMul(in BasePoint, S);
            var rhs = Add(R, ScalarMul(in A, k));
            return EncodePoint(lhs).AsSpan().SequenceEqual(EncodePoint(rhs));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Clamp the first 32 bytes of a SHA-512 hash per RFC 8032</summary>
    private static void ClampScalar(byte[] h)
    {
        h[0] &= 0xF8;   // clear bottom 3 bits
        h[31] &= 0x7F;  // clear top bit
        h[31] |= 0x40;  // set second-to-top bit
    }

    #endregion

    #region SPKI / PKCS8 Encoding (OID 1.3.101.112)

    /// <summary>Encode 32-byte public key as SubjectPublicKeyInfo (DER)</summary>
    public static byte[] EncodeSpki(byte[] publicKey)
    {
        if (publicKey.Length != 32) throw new ArgumentException("Ed25519 public key must be 32 bytes");
        var result = new byte[SpkiPrefix.Length + 32];
        SpkiPrefix.CopyTo(result, 0);
        publicKey.CopyTo(result, SpkiPrefix.Length);
        return result;
    }

    /// <summary>Encode 32-byte seed as PKCS#8 PrivateKeyInfo (DER)</summary>
    public static byte[] EncodePkcs8(byte[] seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes");
        var result = new byte[Pkcs8Prefix.Length + 32];
        Pkcs8Prefix.CopyTo(result, 0);
        seed.CopyTo(result, Pkcs8Prefix.Length);
        return result;
    }

    /// <summary>Decode SubjectPublicKeyInfo → 32-byte public key</summary>
    public static byte[] DecodeSpki(byte[] spki)
    {
        if (spki.Length != SpkiPrefix.Length + 32)
            throw new CryptographicException($"Invalid Ed25519 SPKI length: {spki.Length}");
        if (!spki.AsSpan(0, SpkiPrefix.Length).SequenceEqual(SpkiPrefix))
            throw new CryptographicException("Invalid Ed25519 SPKI header");
        return spki[SpkiPrefix.Length..];
    }

    /// <summary>Decode PKCS#8 PrivateKeyInfo → 32-byte seed</summary>
    public static byte[] DecodePkcs8(byte[] pkcs8)
    {
        if (pkcs8.Length != Pkcs8Prefix.Length + 32)
            throw new CryptographicException($"Invalid Ed25519 PKCS8 length: {pkcs8.Length}");
        if (!pkcs8.AsSpan(0, Pkcs8Prefix.Length).SequenceEqual(Pkcs8Prefix))
            throw new CryptographicException("Invalid Ed25519 PKCS8 header");
        return pkcs8[Pkcs8Prefix.Length..];
    }

    #endregion
}
