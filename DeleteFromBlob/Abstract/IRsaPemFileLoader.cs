using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

namespace DeleteFromBlob.Abstract
{
    public interface IRsaPemFileLoader
    {
        AsymmetricKeyParameter GetPrivateKeyAsKeyParameter(string pathToPrivateKey);
        RSACryptoServiceProvider GetPrivateKeyAsServiceProvider(string pathToPrivateKey);
        AsymmetricKeyParameter GetPublicKeyAsKeyParameter(string pathToPublicKey);
        RSACryptoServiceProvider GetPublicKeyAsServiceProvider(string pathToPublicKey);
    }
}
