using System;
using System.Reflection;
using System.Collections;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace CertificateAPI
{

    public interface ICertificateEmpire
    {
        // Map this according to your needs
        X509Certificate[] Certs { get; set; }
        AsymmetricCipherKeyPair[] KeyPairs { get; set; }
        string[] Names { get; set; }

        string ToString();
    }

    public class CertificateEmpire : ICertificateEmpire
    {
        public X509Certificate[] Certs { get; set; } // [0] = issuer, [1] = subject
        public AsymmetricCipherKeyPair[] KeyPairs { get; set; } // [0] = issuer, [1] = subject
        public string[] Names { get; set; } // [0] = issuer, [1] = subject

        public override string ToString()
        {
            return $@"{Names[0]} public key: {IssuerPublicKey}
            {Names[0]} private key: {IssuerPrivateKey}
            {Names[1]} public key: {SubjectPublicKey}
            {Names[1]} private key: {SubjectPrivateKey}";
        }

        public CertificateEmpire()
        {
            Certs = new X509Certificate[2];
            KeyPairs = new AsymmetricCipherKeyPair[2];
            Names = new string[2];
        }

        public BigInteger IssuerPublicKey
        {
            get
            {
                PropertyInfo propInfo = KeyPairs[0].Private.GetType().GetProperty("PublicExponent");
                return (BigInteger)propInfo.GetValue((object)KeyPairs[0].Private);
            }
        }

        private BigInteger IssuerPrivateKey
        {
            get
            {
                PropertyInfo propInfo = KeyPairs[0].Private.GetType().GetProperty("Exponent");
                return (BigInteger)propInfo.GetValue((object)KeyPairs[0].Private);
            }
        }

        public BigInteger SubjectPublicKey
        {
            get
            {
                PropertyInfo propInfo = KeyPairs[1].Private.GetType().GetProperty("PublicExponent");
                return (BigInteger)propInfo.GetValue((object)KeyPairs[1].Private);
            }
        }

        private BigInteger SubjectPrivateKey
        {
            get
            {
                PropertyInfo propInfo = KeyPairs[1].Private.GetType().GetProperty("Exponent");
                return (BigInteger)propInfo.GetValue((object)KeyPairs[1].Private);
            }
        }

        //public int issuerKeySize;
        //public int certificateKeySize;
    }

    public static class EmpireBuilder
    {
        public static ICertificateEmpire Build(string issuer = "CN=Unnamed Issuer", string subject = "CN=Unnamed MLAPI Development Certificate" )
        {
            ICertificateGenerator cg = new CertGenerator(); // Choose a Certificate Generator that complies with the ICertificateGenerator protocol

            Tuple<X509Certificate, AsymmetricCipherKeyPair> issuerTuple = cg.GenerateIssuerCertificate(issuer);
            Tuple<X509Certificate, AsymmetricCipherKeyPair> subjectTuple = cg.IssueCertificate(issuerTuple.Item1, issuerTuple.Item2.Private, subject);

            CertificateEmpire empire = new CertificateEmpire();

            empire.Certs[0] = issuerTuple.Item1;
            empire.Certs[1] = subjectTuple.Item1;

            empire.KeyPairs[0] = issuerTuple.Item2;
            empire.KeyPairs[1] = subjectTuple.Item2;

            empire.Names[0] = issuer;
            empire.Names[1] = subject;

            return empire;
        }
    }


}
