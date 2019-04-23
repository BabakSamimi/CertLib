using System;
using System.Reflection;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace CertificateAPI
{
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
}
