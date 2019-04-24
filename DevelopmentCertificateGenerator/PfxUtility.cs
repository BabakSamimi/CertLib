using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace CertificateAPI
{
    public static class PfxUtility
    {
        // Converts a PFX-container in base64 into a X509Certificate
        public static X509Certificate GetPfxFromBase64(string b64, string alias)
        {

            if (alias != null)
            {
                alias = $"{alias}_key";
            }
            else
                throw new ArgumentNullException("Alias parameter was null");

            if (b64 == null)
                throw new ArgumentNullException("b64 parameter was null");

            byte[] buffer;

            if (File.Exists(b64))
            {
                using (var filestream = File.OpenRead(b64))
                {
                    buffer = new byte[filestream.Length];

                    filestream.Read(buffer, 0, (int)filestream.Length); // This might truncuate the buffer if the length is bigger than 2^32
                }
            }
            else
                throw new FileNotFoundException();

            byte[] bytes = Base64.Decode(System.Text.Encoding.UTF8.GetString(buffer));
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();


            using (MemoryStream memstream = new MemoryStream(bytes))
            {
                store.Load(memstream, "".ToCharArray());
            }

            return store.GetCertificate(alias).Certificate;

        }

        // Returns a base64 encoded PFX-container based on the CA cert
        // NOTE: The password is empty.
        public static string ToPfxBase64(X509Certificate issuerCertificate, AsymmetricCipherKeyPair issuerKeyPair)
        {
            // https://7thzero.com/blog/bouncy-castle-create-a-basic-certificate
            // https://stackoverflow.com/questions/44755155/store-pkcs12-container-pfx-with-bouncycastle
            // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/pkcs/examples/PKCS12Example.cs
            // https://stackoverflow.com/questions/30039639/exporting-or-saving-cx509privatekey/33596494#33596494

            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            X509CertificateEntry certEntry = new X509CertificateEntry(issuerCertificate);
            AsymmetricKeyEntry keyEntry = new AsymmetricKeyEntry(issuerKeyPair.Private);

            store.SetKeyEntry(issuerCertificate.IssuerDN.ToString() + "_key", keyEntry, new X509CertificateEntry[] { certEntry });

            byte[] pfx;

            using (var memStream = new MemoryStream())
            {
                store.Save(memStream, "".ToCharArray(), new SecureRandom());
                pfx = memStream.ToArray();
            }

            pfx = Pkcs12Utilities.ConvertToDefiniteLength(pfx, "".ToCharArray()); // Empty password

            return Convert.ToBase64String(pfx);
        }
    }
}
