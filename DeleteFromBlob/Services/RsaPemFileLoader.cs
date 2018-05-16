using System;
using System.IO;
using System.Security.Cryptography;
using DeleteFromBlob.Abstract;
using Org.BouncyCastle.Crypto;

namespace DeleteFromBlob.Services
{
    public class RsaPemFileLoader : IRsaPemFileLoader
    {
        private readonly IRsaPemLoader _rsaPemLoader;
        public RsaPemFileLoader()
        {
            _rsaPemLoader = new RsaPemLoader();
        }

        public AsymmetricKeyParameter GetPublicKeyAsKeyParameter(string pathToPublicKey)
        {
            if (!File.Exists(pathToPublicKey))
            {
                return null;
            }

            try
            {
                using (var reader = File.OpenText(pathToPublicKey))
                {
                    return _rsaPemLoader.GetPublicKeyAsKeyParameter(reader);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        public AsymmetricKeyParameter GetPrivateKeyAsKeyParameter(string pathToPrivateKey)
        {
            if (!File.Exists(pathToPrivateKey))
            {
                return null;
            }

            try
            {
                using (var reader = File.OpenText(pathToPrivateKey))
                {
                    return _rsaPemLoader.GetPrivateKeyAsKeyParameter(reader);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        public RSACryptoServiceProvider GetPublicKeyAsServiceProvider(string pathToPublicKey)
        {
            try
            {
                using (var reader = File.OpenText(pathToPublicKey))
                {
                    return _rsaPemLoader.GetPublicKeyAsServiceProvider(reader);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        public RSACryptoServiceProvider GetPrivateKeyAsServiceProvider(string pathToPrivateKey)
        {
            try
            {
                using (var reader = File.OpenText(pathToPrivateKey))
                {
                    return _rsaPemLoader.GetPrivateKeyAsServiceProvider(reader);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }
    }
}