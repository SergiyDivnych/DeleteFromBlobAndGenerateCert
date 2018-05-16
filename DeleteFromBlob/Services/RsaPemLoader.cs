using System.IO;
using System.Security.Cryptography;
using DeleteFromBlob.Abstract;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace DeleteFromBlob.Services
{
    public class RsaPemLoader : IRsaPemLoader
    {
        public AsymmetricKeyParameter GetPrivateKeyAsKeyParameter(TextReader reader)
        {
            var param = new PemReader(reader).ReadObject();

            if (param.GetType() == typeof(RsaPrivateCrtKeyParameters))
            {
                return (AsymmetricKeyParameter) param;
            }

            var rsaKeyParameters = (AsymmetricCipherKeyPair) param;
            return rsaKeyParameters.Private;
        }

        public RSACryptoServiceProvider GetPrivateKeyAsServiceProvider(TextReader reader)
        {
            var rsaKeyParameters = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters) rsaKeyParameters.Private));
            return rsa;

        }

        public AsymmetricKeyParameter GetPublicKeyAsKeyParameter(TextReader reader)
        {
            return (RsaKeyParameters) new PemReader(reader).ReadObject();
        }

        public RSACryptoServiceProvider GetPublicKeyAsServiceProvider(TextReader reader)
        {
            var rsaKeyParameters = (RsaKeyParameters) new PemReader(reader).ReadObject();
            var rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            return rsa;
        }
    }
}
