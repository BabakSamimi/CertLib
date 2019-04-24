using System;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace CertificateAPI
{
    // TODO: Rework this, don't have to limit to a Tuple
    public interface ICertificateGenerator
    {
        Tuple<X509Certificate, AsymmetricCipherKeyPair> GenerateIssuerCertificate(string issuerName);
        Tuple<X509Certificate, AsymmetricCipherKeyPair> IssueCertificate(X509Certificate issuer, AsymmetricKeyParameter issuerPrivate, string subjectName);
        
    }
}
