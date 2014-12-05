using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool
{
    class Program
    {
        static void Main(string[] args)
        {
            string regLoc = "SOFTWARE\\%USERNAME%";
            regLoc = Environment.ExpandEnvironmentVariables(regLoc);
            RSAEncryption RSA = new RSAEncryption();
            RSA.WriteKeyAndCipherTextToFile();
            Console.ReadLine();
        }
    }
}
