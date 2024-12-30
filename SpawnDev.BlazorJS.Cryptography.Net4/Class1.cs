using System;
using Org.BouncyCastle;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;

namespace SpawnDev.BlazorJS.Cryptography.Net4
{
    public class Class1
    {

        public void Grrr()
        {

            X9ECParameters curve = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ecparam = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(ecparam, new SecureRandom()));

            AsymmetricCipherKeyPair ackp1 = generator.GenerateKeyPair();
            AsymmetricCipherKeyPair ackp2 = generator.GenerateKeyPair();

            ECDHWithKdfBasicAgreement agreement = new ECDHWithKdfBasicAgreement("2.16.840.1.101.3.4.42", new ECDHKekGenerator(DigestUtilities.GetDigest("SHA256")));
            agreement.Init(ackp1.Private);
            BigInteger agInt = agreement.CalculateAgreement(ackp2.Public);
            byte[] aeskey = agInt.ToByteArrayUnsigned();
        }
    }
}
