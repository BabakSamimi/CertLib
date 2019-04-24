using System;
using System.IO;
using System.Reflection;
using System.Collections;
using System.Diagnostics;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Utilities.Encoders;

/*
 * How self-signing works (development purpose):
 * I am a server and I want to make myself a certification that is self-signed.
 * This means that I'll have to be my own CA/Issuer.
 * This also means that we'll have to generate 2 key pairs.
 * One key pair will be used to sign our own certificate, ultimately this key pair is literally the same.
 * 
 * 
 * Objective:
 * Input: Issuer Name and Subject Name.
 * Output: A base64 encoded PFX-file and a base64 encoded certificate
 * 
 * Generate RSA Key pair
 * Create certificate with the given key pair
 * 
 * Unity Extension:
 * 
 */
namespace CertificateAPI
{

    internal class RandomGenerator
    {
        internal CryptoApiRandomGenerator randomGenerator;
        internal SecureRandom random;

        internal RandomGenerator()
        {
            randomGenerator = new CryptoApiRandomGenerator();
            random = new SecureRandom(randomGenerator);
        }
    }

    internal static class RSAGenerator
    {

        private static KeyGenerationParameters keyGenParams;
        private static RsaKeyPairGenerator rsaKeyPairGenerator;

        // Generates X-bits RSA key pair
        public static AsymmetricCipherKeyPair Generate(int bits = 2048)
        {
            RandomGenerator rng = new RandomGenerator();

            keyGenParams = new KeyGenerationParameters(rng.random, bits);
            rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(keyGenParams);

            return rsaKeyPairGenerator.GenerateKeyPair();
        }
    }

    public class CertGenerator : ICertificateGenerator
    {

        /// <summary>
        /// Generates the issuer certificate and returns a tuple with the certificate and its key pair.
        /// </summary>
        /// <returns>The issuer certificate.</returns>
        /// <param name="issuerName">Issuer name.</param>
        public Tuple<X509Certificate, AsymmetricCipherKeyPair> GenerateIssuerCertificate(string issuerName)
        {
            RandomGenerator rng = new RandomGenerator();

            // The limit on these are 30 days because we say so
            DateTime startDate = DateTime.UtcNow.Date;
            DateTime expireDate = startDate.AddDays(30);

            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), rng.random);

            X509Name issuerDN = new X509Name(issuerName);

            // 2048 bits rsa pair
            AsymmetricCipherKeyPair issuerPair = RSAGenerator.Generate(); // 2048-bits

            X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

            // Generate the self-signed CA cert
            certGenerator.SetSerialNumber(serialNumber);
            certGenerator.SetIssuerDN(issuerDN);
            certGenerator.SetSubjectDN(issuerDN);
            certGenerator.SetNotBefore(startDate);
            certGenerator.SetNotAfter(expireDate);
            certGenerator.SetPublicKey(issuerPair.Public);

            // Extensions
            var issuerKeyIdentifier = new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerPair.Public).GetEncoded(), new GeneralNames(new GeneralName(issuerDN)), serialNumber);
            certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, issuerKeyIdentifier);
            certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(true)); // Parameters for a CA cert

            rng = new RandomGenerator();
            ISignatureFactory issuerSignature = new Asn1SignatureFactory("SHA512WITHRSA", issuerPair.Private, rng.random);

            return new Tuple<X509Certificate, AsymmetricCipherKeyPair>(certGenerator.Generate(issuerSignature), issuerPair); // Create and return CA Cert with keypair

        }

        /// <summary>
        /// Issues a certificate and returns a tuple with the certificate and its key pair.
        /// </summary>
        /// <returns>The certificate.</returns>
        /// <param name="issuer">Issuer.</param>
        /// <param name="issuerPrivate">Issuer private.</param>
        /// <param name="subjectName">Subject name.</param>
        public Tuple<X509Certificate, AsymmetricCipherKeyPair> IssueCertificate(X509Certificate issuer, AsymmetricKeyParameter issuerPrivate, string subjectName)
        {
            RandomGenerator rng = new RandomGenerator();

            // The limit on these are 30 days because we say so
            DateTime startDate = DateTime.UtcNow.Date;
            DateTime expireDate = startDate.AddDays(30);

            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), rng.random);

            X509Name subjectDN = new X509Name(subjectName);

            // 2048 bits rsa pair
            AsymmetricCipherKeyPair subjectPair = RSAGenerator.Generate(); // 2048-bits

            X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

            certGenerator.SetSerialNumber(serialNumber);
            certGenerator.SetIssuerDN(issuer.IssuerDN);
            certGenerator.SetSubjectDN(subjectDN);
            certGenerator.SetNotBefore(startDate);
            certGenerator.SetNotAfter(expireDate);
            certGenerator.SetPublicKey(subjectPair.Public);

            // Extensions
            var subjectKeyIdentifier = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPair.Public));
            certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifier);
            //certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false)); // Parameters for a non-CA cert

            rng = new RandomGenerator();
            ISignatureFactory issuerSignature = new Asn1SignatureFactory("SHA512WITHRSA", issuerPrivate, rng.random);
            return new Tuple<X509Certificate, AsymmetricCipherKeyPair>(certGenerator.Generate(issuerSignature), subjectPair);
        }
    }
}

