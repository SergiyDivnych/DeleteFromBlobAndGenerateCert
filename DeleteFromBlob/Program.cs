using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Azure.WebJobs;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using CERTENROLLLib;
using DeleteFromBlob.Abstract;
using DeleteFromBlob.Services;

namespace DeleteFromBlob
{
    class Program
    {
        private static string connectionString =
        "DefaultEndpointsProtocol";
        private static IRsaService _rsaService;
        private static IRsaPemFileLoader _rsaPemFileLoader;

        static void Main()
        {
            var config = new JobHostConfiguration();

            if (config.IsDevelopment)
            {
                config.UseDevelopmentSettings();
            }
            _rsaService = new RsaService();
            _rsaPemFileLoader = new RsaPemFileLoader();
            //FindAllFolders();
            //FindAllExceptLastDaysFolders();

            //delete all data if needed
            //DeleteAllExceptLastDays();

            //Generate certificate
            //CreateSelfSignedCertificate("nameForCertificate");
            //GenerateSelfSignedCertificate("nameForCertificate", "nameForCertificate", null, 1024);
            //GenerateCACertificate("nameForCertificate", 2048);
        }

        #region BlobOperations
        private static void FindAllFolders()
        {
            FileStream ostrm;
            StreamWriter writer;
            TextWriter oldOut = Console.Out;
            try
            {
                ostrm = new FileStream("./allContainers.txt", FileMode.OpenOrCreate, FileAccess.Write);
                writer = new StreamWriter(ostrm);
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot open Redirect.txt for writing");
                Console.WriteLine(e.Message);
                return;
            }
            Console.SetOut(writer);
            List<string> blobs = new List<string>();
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(connectionString);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            IEnumerable<CloudBlobContainer> containers = blobClient.ListContainers();

            foreach (CloudBlobContainer item in containers)
            {
                foreach (IListBlobItem blob in item.ListBlobs())
                {
                    blobs.Add(string.Format("{0}", blob.Uri.Segments[2]));
                    Console.WriteLine(blob.Container.Name + " has been added");
                }
            }
            Console.WriteLine(blobs.Count + " folders has been found");
            Console.SetOut(oldOut);
            writer.Close();
            ostrm.Close();
        }

        private static void FindAllExceptLastDaysFolders()
        {
            FileStream ostrm;
            StreamWriter writer;
            TextWriter oldOut = Console.Out;
            var days = 60;
            try
            {
                ostrm = new FileStream("./" + days + "days_exclude.txt", FileMode.OpenOrCreate, FileAccess.Write);
                writer = new StreamWriter(ostrm);
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot open Redirect.txt for writing");
                Console.WriteLine(e.Message);
                return;
            }
            Console.SetOut(writer);
            List<string> blobs = new List<string>();
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(connectionString);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            IEnumerable<CloudBlobContainer> containers = blobClient.ListContainers();

            foreach (CloudBlobContainer item in containers)
            {
                var oldContent = item.ListBlobs("", true).OfType<CloudBlockBlob>().Where(b => (DateTime.UtcNow.AddDays(-days) > b.Properties.LastModified.Value.DateTime)).ToList();
                foreach (IListBlobItem blob in oldContent)
                {
                    blobs.Add(string.Format("{0}", blob.Uri.Segments[2]));
                    Console.WriteLine(blob.Container.Name + " has been added");
                }
            }
            Console.WriteLine(blobs.Count + " folders has been found");
            Console.SetOut(oldOut);
            writer.Close();
            ostrm.Close();
        }

        private static void DeleteAllExceptLastDays()
        {
            var lastDays = 175;
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(connectionString);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            IEnumerable<CloudBlobContainer> containers = blobClient.ListContainers();

            foreach (CloudBlobContainer item in containers)
            {
                var oldContent = item.ListBlobs("", true).OfType<CloudBlockBlob>().Where(b => (DateTime.UtcNow.AddDays(-lastDays) > b.Properties.LastModified.Value.DateTime)).ToList();

                foreach (IListBlobItem blob in oldContent)
                {
                    var delete = blob.Container.DeleteIfExists();
                    if (delete)
                    {
                        Console.WriteLine(blob.Container.Name + " has been deleted");
                    }
                }
            }
        }
        #endregion

        #region Certificate
        public static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 1024;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid = new CObjectId();
            oid.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // SSL server
            var oidlist = new CObjectIds();
            oidlist.Add(oid);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            cert.NotBefore = DateTime.Now;
            // this cert expires immediately. Change to whatever makes sense for you
            cert.NotAfter = cert.NotBefore.AddYears(2);
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = subjectName; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
                                                 // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
                                                                   // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            );

            addCertToStore(certificate, StoreName.Root, StoreLocation.LocalMachine);
            return certificate;
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name
            var subjectDN = new X509Name("CN=" + subjectName);
            var issuerDN = new X509Name("CN=" + issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);
            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            // correcponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);

            using (var sw = File.CreateText(Path.Combine("D:\\", "PrivateKey")))
            {
                var pw = new PemWriter(sw);
                pw.WriteObject(subjectKeyPair.Private);
            }

            using (var sw = File.CreateText(Path.Combine("D:\\", "PublicKey")))
            {
                var pw = new PemWriter(sw);
                pw.WriteObject(subjectKeyPair.Public);
            }
            string encryptionKey = "*****";

            var a = Encrypt(encryptionKey);

            var pass = "****";
            // merge into X509Certificate2
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded(), pass);

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);

            string text = System.IO.File.ReadAllText(@"C:\xampp\apache\conf\ssl.crt\server.crt");
            UTF8Encoding encoding = new System.Text.UTF8Encoding();
            byte[] byteCert = encoding.GetBytes(text);
            X509Certificate2 uberCert = new X509Certificate2();
            uberCert.Import(byteCert);
            Console.WriteLine("Has privateKey:" + uberCert.HasPrivateKey.ToString());
            Console.WriteLine("PrivateKey: \n" + uberCert.PrivateKey);

            addCertToStore(x509, StoreName.Root, StoreLocation.CurrentUser);
            using (x509)
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(
                    Convert.ToBase64String(x509.RawData, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");
                builder.ToString();

            }
            return x509;
        }

        public static string Encrypt(string message)
        {
            var publicKey = _rsaPemFileLoader.GetPublicKeyAsServiceProvider("D:\\PublicKey");
            return publicKey == null ? "Exception when read file" : _rsaService.Encrypt(message, publicKey);
        }

        public static AsymmetricKeyParameter GenerateCACertificate(string subjectName, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name
            var subjectDN = new X509Name("CN=" + subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);
            var pass =
                "**********************";
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded(), pass);
            addCertToStore(x509, StoreName.Root, StoreLocation.CurrentUser);

            return issuerKeyPair.Private;
        }

        public static bool addCertToStore(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, System.Security.Cryptography.X509Certificates.StoreName st, System.Security.Cryptography.X509Certificates.StoreLocation sl)
        {
            bool bRet = false;

            try
            {
                X509Store store = new X509Store(st, sl);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);

                store.Close();
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.InnerException);
            }
            return bRet;
        }
        #endregion
    }
}
