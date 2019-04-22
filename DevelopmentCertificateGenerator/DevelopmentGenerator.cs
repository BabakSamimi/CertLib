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
using Org.BouncyCastle.Utilities.IO.Pem;

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

    public static class Pfx
    {
        // Reads in a base64 string and converts it into a PFX file
        public static void GetPfxBase64(string b64, string alias)
        {
            byte[] bytes = Base64.Decode(b64);
            //Pkcs12Store store = new Pkcs12StoreBuilder().Build();


            /*using (MemoryStream memstream = new MemoryStream(bytes))
            {
                store.Load(memstream, "".ToCharArray());
            }*/

            X509Certificate cert = new X509CertificateParser().ReadCertificate(bytes);

            Console.WriteLine(cert.ToString());

        }
    }

    public struct CertificateEmpire
    {

        public AsymmetricCipherKeyPair issuerKeyPair;
        public AsymmetricCipherKeyPair subjectKeyPair;

        public string issuerName;
        public string subjectName;

        public X509Certificate issuerCertificate;
        public X509Certificate subjectCertificate;

        public BigInteger IssuerPublicKey
        {
            get
            {
                PropertyInfo propInfo = issuerKeyPair.Private.GetType().GetProperty("PublicExponent");
                return (BigInteger)propInfo.GetValue((object)issuerKeyPair.Private);
            }
        }

        private BigInteger IssuerPrivateKey
        {
            get
            {
                PropertyInfo propInfo = issuerKeyPair.Private.GetType().GetProperty("Exponent");
                return (BigInteger)propInfo.GetValue((object)issuerKeyPair.Private);
            }
        }

        public BigInteger SubjectPublicKey
        {
            get
            {
                PropertyInfo propInfo = subjectKeyPair.Private.GetType().GetProperty("PublicExponent");
                return (BigInteger)propInfo.GetValue((object)subjectKeyPair.Private);
            }
        }

        private BigInteger SubjectPrivateKey
        {
            get
            {
                PropertyInfo propInfo = subjectKeyPair.Private.GetType().GetProperty("Exponent");
                return (BigInteger)propInfo.GetValue((object)subjectKeyPair.Private);
            }
        }

        // Creates a PFX file in base64 based on the CA cert
        // NOTE: The password is empty.
        public string ToPfxBase64()
        {
            // https://7thzero.com/blog/bouncy-castle-create-a-basic-certificate
            // https://stackoverflow.com/questions/44755155/store-pkcs12-container-pfx-with-bouncycastle
            // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/pkcs/examples/PKCS12Example.cs
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            X509CertificateEntry certEntry = new X509CertificateEntry(issuerCertificate);

            store.SetCertificateEntry(issuerCertificate.IssuerDN.ToString(), certEntry);
            AsymmetricKeyEntry keyEntry = new AsymmetricKeyEntry(issuerKeyPair.Private);
            store.SetKeyEntry(issuerCertificate.IssuerDN.ToString() + "_key", keyEntry, new X509CertificateEntry[] { certEntry });


            //IDictionary bagAttr = new Hashtable();

            //FileStream file = File.Create("certz.pfx");
            //store.Save(file, "".ToCharArray(), new SecureRandom());

            byte[] pfx;

            try
            {

                using (var memStream = new MemoryStream())
                {
                    store.Save(memStream, "".ToCharArray(), new SecureRandom());
                    pfx = memStream.ToArray();
                }
            }
            catch(Exception e)
            {
                throw e;
            }

            var result = Pkcs12Utilities.ConvertToDefiniteLength(pfx);

            return Convert.ToBase64String(result);
        }


        public override string ToString()
        {

            return $@"{issuerName} public key: {IssuerPublicKey}
            {issuerName} private key: {IssuerPrivateKey}
            {subjectName} public key: {SubjectPublicKey}
            {subjectName} private key: {SubjectPrivateKey}";
        }

        //public int issuerKeySize;
        //public int certificateKeySize;
    }

    public static class CertGenerator
    {
        /// <summary>
        /// Generates a CertificateEmpire which contains a CA cert and a subject cert and their RSA key pairs
        /// These certs are only used for development/testing purposes, do not use these certs for production.
        /// </summary>
        /// <returns>CertificateEmpire-object</returns>
        /// <param name="issuerName">Issuer name.</param>
        /// <param name="subjectName">Subject name.</param>
        public static CertificateEmpire? GenerateEmpire(string issuerName, string subjectName)
        {
            try
            {
                RandomGenerator rng = new RandomGenerator();

                // The limit on these are 30 days because we say so
                DateTime startDate = DateTime.UtcNow.Date;
                DateTime expireDate = startDate.AddDays(30);

                BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), rng.random);

                X509Name issuerDN = new X509Name(issuerName);
                X509Name subjectDN = new X509Name(subjectName);

                // 2048 bits rsa pair
                AsymmetricCipherKeyPair issuerPair = RSAGenerator.Generate(2048);
                AsymmetricCipherKeyPair subjectPair = RSAGenerator.Generate(2048);

                X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

                rng = new RandomGenerator();

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

                ISignatureFactory issuerSignature = new Asn1SignatureFactory("SHA512WITHRSA", issuerPair.Private, rng.random);
                X509Certificate issuerCert = certGenerator.Generate(issuerSignature); // Create CA Cert

                // Issue a cert
                certGenerator = new X509V3CertificateGenerator();

                certGenerator.SetSerialNumber(serialNumber);
                certGenerator.SetIssuerDN(issuerDN);
                certGenerator.SetSubjectDN(subjectDN);
                certGenerator.SetNotBefore(startDate);
                certGenerator.SetNotAfter(expireDate);
                certGenerator.SetPublicKey(subjectPair.Public);

                // Extensions
                var subjectKeyIdentifier = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPair.Public));
                certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifier);
                //certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false)); // Parameters for a non-CA cert


                issuerSignature = new Asn1SignatureFactory("SHA512WITHRSA", issuerPair.Private, rng.random);
                X509Certificate subjectCert = certGenerator.Generate(issuerSignature);

                return new CertificateEmpire()
                {
                    issuerKeyPair = issuerPair,
                    subjectKeyPair = subjectPair,
                    issuerCertificate = issuerCert,
                    subjectCertificate = subjectCert,
                    issuerName = issuerName,
                    subjectName = subjectName
                };

            } catch(Exception e)
            {
                return null;
                throw e;
            }
        }
    }
}

