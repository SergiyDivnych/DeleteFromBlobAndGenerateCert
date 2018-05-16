using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

namespace DeleteFromBlob.Abstract
{
    public interface IRsaService
    {
        AsymmetricCipherKeyPair GenerateKeys();
        string Encrypt(string text, RSACryptoServiceProvider csp);
        string Decrypt(string cypherText, RSACryptoServiceProvider csp);
        string Sign(string text, RSACryptoServiceProvider cspPrivatKey);
        bool Verify(string text, string signature, RSACryptoServiceProvider cspPublicKey);
    }
}
