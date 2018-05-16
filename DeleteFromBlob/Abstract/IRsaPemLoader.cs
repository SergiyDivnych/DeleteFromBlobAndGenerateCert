using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

namespace DeleteFromBlob.Abstract
{
    public interface IRsaPemLoader
    {
        
        AsymmetricKeyParameter GetPrivateKeyAsKeyParameter(TextReader reader);
        RSACryptoServiceProvider GetPrivateKeyAsServiceProvider(TextReader reader);
        AsymmetricKeyParameter GetPublicKeyAsKeyParameter(TextReader reader);
        RSACryptoServiceProvider GetPublicKeyAsServiceProvider(TextReader reader);
    }
}