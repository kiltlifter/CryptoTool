using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Security.Principal;

namespace CryptoTool
{
    class RSAEncryption
    {

        public void WriteKeyAndCipherTextToFile()
        {
            try
            {
                Console.WriteLine("File name for RSA keys: ");
                string keyFileName = Console.ReadLine();
                Console.WriteLine("File name for cipher text: ");
                string cipherTextFileName = Console.ReadLine();
                Console.WriteLine("Password: ");
                string plainText = Console.ReadLine();
                string rsaKeys = GenerateRSAKeys();
                System.IO.File.WriteAllText(keyFileName, rsaKeys);
                byte[] cipherText = EncryptPasswordSimple(plainText, rsaKeys);
                System.IO.File.WriteAllBytes(cipherTextFileName, cipherText);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        public void EncryptionTesting(string Password, string RegistryLocation)
        {
            if (!DoesKeyExist(RegistryLocation))
            {
                WriteKeysToRegistryLocation(RegistryLocation);
                Console.WriteLine("Creating RSA keys...");
            }
            //byte[] cipherText = EncryptPassword(Password, RegistryLocation);
            byte[] cipherText = System.IO.File.ReadAllBytes("C:\\Users\\blackglas\\Documents\\cipherTest.txt");
            string plainText = DecryptPassword(cipherText, RegistryLocation);
            //Console.WriteLine("Encrypted Data:\n\n" + cipherText.ToString() + "\n\n");
            //System.IO.File.WriteAllBytes("C:\\Users\\blackglas\\Documents\\cipherTest.txt", cipherText);
            Console.WriteLine("Decrypted Password:\n\n" + plainText + "\n\n");
        }

        private string GenerateRSAKeys()
        {
            string keys = string.Empty;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                keys = RSA.ToXmlString(true);
            }
            return keys;
        }

        public void WriteKeysToRegistryLocation(string RegistryLocation)
        {
            try
            {
                if (IsAdmin())
                {
                    Registry.LocalMachine.CreateSubKey(RegistryLocation);
                    RegistryKey regKey = Registry.LocalMachine.OpenSubKey(RegistryLocation, true);
                
                    String rsaKeys = GenerateRSAKeys();
                    regKey.SetValue("RSA_KEY", rsaKeys, RegistryValueKind.String);
                    regKey.Close();
                }
                else
                {
                    Console.WriteLine("Permission Denied. You must run as administrator.");
                    Console.ReadLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        public string ReadKeysFromRegistry(string RegistryLocation)
        {
            string rsaKeys = string.Empty;
            try
            {
                RegistryKey regKey = Registry.LocalMachine.OpenSubKey(RegistryLocation, false);
                rsaKeys = regKey.GetValue("RSA_KEY") as string;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            return rsaKeys;
        }

        public byte[] EncryptPassword(string password, string RegistryLocation)
        {
            byte[] encryptedData = new byte[] { };
            try
            {
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                string rsaKeys = ReadKeysFromRegistry(RegistryLocation);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    byte[] passToByte = ByteConverter.GetBytes(password);
                    rsa.FromXmlString(rsaKeys);
                    encryptedData = rsa.Encrypt(passToByte, false);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            return encryptedData;
        }

        public string DecryptPassword(byte[] cipherText, string RegistryLocation)
        {
            string plainText = string.Empty;
            try
            {
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                string rsaKeys = ReadKeysFromRegistry(RegistryLocation);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(rsaKeys);
                    byte[] decryptedData = rsa.Decrypt(cipherText, false);
                    plainText = ByteConverter.GetString(decryptedData);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            return plainText;
        }

        public byte[] EncryptPasswordSimple(string Password, string RSAKeys)
        {
            byte[] encryptedData = new byte[] { };
            try
            {
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    byte[] passToByte = ByteConverter.GetBytes(Password);
                    rsa.FromXmlString(RSAKeys);
                    encryptedData = rsa.Encrypt(passToByte, false);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            return encryptedData;
        }

        public string DecryptPasswordSimple(byte[] CipherText, string RSAKeys)
        {
            string plainText = string.Empty;
            try
            {
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(RSAKeys);
                    byte[] decryptedData = rsa.Decrypt(CipherText, false);
                    plainText = ByteConverter.GetString(decryptedData);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            return plainText;
        }

        public bool DoesKeyExist(string RegistryLocation)
        {
            bool keyExists;
            try
            {
                RegistryKey regKey = Registry.LocalMachine.OpenSubKey(RegistryLocation, false);
                object value = regKey.GetValue("RSA_KEY", null);
                if (value != null)
                {
                    keyExists = true;
                }
                else
                {
                    keyExists = false;
                }
            }
            catch (Exception)
            {
                keyExists = false;
            }
            return keyExists;
        }

        public bool IsAdmin()
        {
            bool isAdmin;
            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine(ex);
                isAdmin = false;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                isAdmin = false;
            }
            return isAdmin;
        }
    }
}
