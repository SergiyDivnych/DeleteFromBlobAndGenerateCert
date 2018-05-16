using System;
using System.Security.Cryptography;
using System.Text;
using DeleteFromBlob.Abstract;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace DeleteFromBlob.Services
{
    public class RsaService : IRsaService
    {
        public AsymmetricCipherKeyPair GenerateKeys()
        {
            var csp = new RSACryptoServiceProvider(1024);

            return DotNetUtilities.GetRsaKeyPair(csp);
        }

        public string Encrypt(string text, RSACryptoServiceProvider csp)
        {
            var bytesPlainTextData = Encoding.UTF8.GetBytes(text);

            var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

            return Convert.ToBase64String(bytesCypherText);
        }

        public string Decrypt(string cypherText, RSACryptoServiceProvider csp)
        {
            var bytesCypherText = Convert.FromBase64String(cypherText);

            byte[] bytesPlainTextData;
            try
            {
                bytesPlainTextData = csp.Decrypt(bytesCypherText, false);
            }
            catch (Exception)
            {
                return "Private key is not valid";
            }

            return Encoding.UTF8.GetString(bytesPlainTextData);
        }

        public string Sign(string text, RSACryptoServiceProvider cspPrivatKey)
        {
            if (cspPrivatKey == null)
            {
                throw new ArgumentException("RSACryptoServiceProvider is null");
            }

            var sha1 = new SHA1Managed();
            var encoding = new UTF8Encoding();

            var data = encoding.GetBytes(text);
            var hash = sha1.ComputeHash(data);

            var sign = cspPrivatKey.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
            return Convert.ToBase64String(sign);

        }

        public bool Verify(string text, string signature, RSACryptoServiceProvider cspPublicKey)
        {
            if (cspPublicKey == null)
            {
                throw new ArgumentException("RSACryptoServiceProvider is null");
            }

            var sign = Convert.FromBase64String(signature);

            var sha1 = new SHA1Managed();
            var encoding = new UTF8Encoding();
            var data = encoding.GetBytes(text);
            var hash = sha1.ComputeHash(data);

            return cspPublicKey.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), sign);
        }
    }
}
