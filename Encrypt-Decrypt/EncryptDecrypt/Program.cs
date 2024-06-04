using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace EncryptDecrypt
{
    internal class Program
    {
        private const int PADDING_LENGTH = 50;

        static void Main(string[] args)
        {
            var ed = Prompt("Do you want to [E]ncrypt or [D]ecrypt?");
            switch (ed.ToLower())
            {
                case "e":
                    HandleEncrypt();
                    break;
                case "d":
                    HandleDecrypt();
                    break;
                default:
                    break;
            }



        }

        private static void HandleDecrypt()
        {
            var key = Prompt("What is your encryption key?");
#if DEBUG
            key = "HjzFz/GPX7o1sOeLrhH0GvDY7S9GORhqlVD9iUsgxmA=";
#endif

#if DEBUG
            var encryptedPath = "../../Encrypted.csv";
            Console.WriteLine($"Using Path {encryptedPath}");
#else
                    var encryptedPath = Prompt("Specify the path to the document you want to encrypt").Replace("\"", "");
#endif
            var directory = Path.GetDirectoryName(encryptedPath);
            var file = Path.GetFileName(encryptedPath);
            string decryptedPath = Path.Combine(directory, $"decrypted {file}");
            if (File.Exists(decryptedPath))
            {
                Prompt($"The file {decryptedPath} already exist. You can make a backup of it now. It will be overwritten. Press [Enter]");
                File.WriteAllText(decryptedPath, "");
            }

            var lines = File.ReadAllLines(encryptedPath);
            foreach (string line in lines)
            {
                var columns = line.Split('\t');
                var content = AesDecrypt(key, columns[1], columns[2]);
#if DEBUG
                Console.WriteLine($"{columns[0]}: {content}");
#endif
                File.AppendAllText(decryptedPath, $"{columns[0]}: {content}\r\n");
            }
            Prompt($"All done. Your decrypted file is at {decryptedPath}");
        }

        private static void HandleEncrypt()
        {
            var key = Prompt("Paste your encryption key. If you don't have one, leave it blank and I'll generate one for you.");
            if (string.IsNullOrEmpty(key))
            {
#if DEBUG
                key = "HjzFz/GPX7o1sOeLrhH0GvDY7S9GORhqlVD9iUsgxmA=";
#else
                        key = GenerateKey();
#endif
                Console.WriteLine($"Please make note of your encryption key: {key}");
            }
#if DEBUG
            var plainPath = "../../Decrypted.txt";
            Console.WriteLine($"Using Path: {plainPath}");
#else
                    var plainPath = Prompt("Specify the path to the document you want to encrypt").Replace("\"", "");
#endif

            var directory = Path.GetDirectoryName(plainPath);
            var file = Path.GetFileName(plainPath);
            string encryptedPath = Path.Combine(directory, $"encrypted {file}");
            if (File.Exists(encryptedPath))
            {
                Prompt($"The file {encryptedPath} already exist. You can make a backup of it now. It will be overwritten. Press [Enter]");
                File.WriteAllText(encryptedPath, "");
            }

            var lines = File.ReadAllLines(plainPath);
            foreach (var line in lines)
            {
                var columns = line.Split('\t');
                var enc = AesEncrypt(key, columns[1]);
                File.AppendAllText(encryptedPath, $"{columns[0]}\t{enc.Item1}\t{enc.Item2}\r\n");
            }
            Prompt($"All done. Your encrypted file is at {encryptedPath}");
        }

        private static string Prompt(string prompt)
        {
            Console.WriteLine(prompt);
            return Console.ReadLine();
        }
        private static string GenerateKey()
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.KeySize = 256;
                aesAlgorithm.GenerateKey();
                return Convert.ToBase64String(aesAlgorithm.Key);
            }
        }

        public static byte[] AesGenerateIv()
        {
            var rng = new RNGCryptoServiceProvider();
            byte[] ivBytes = new byte[16];
            rng.GetBytes(ivBytes);
            return ivBytes;
        }

        public static Tuple<string, string> AesEncrypt(string key, string data)
        {
            if (data.Length < PADDING_LENGTH)
            {
                data = data.PadRight(PADDING_LENGTH, '\0');
            }
            byte[] plainBytes = Encoding.UTF8.GetBytes(data);
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] ivBytes = AesGenerateIv();
            using (var aes = AesCryptoServiceProvider.Create())
            {

                // http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
                // https://stephenhaunts.com/2013/03/04/cryptography-in-net-advanced-encryption-standard-aes/
                aes.Mode = CipherMode.CBC;// default and recommended
                aes.Padding = PaddingMode.PKCS7; // default and recommended
                aes.KeySize = 256;

                var encryptor = aes.CreateEncryptor(keyBytes, ivBytes);

                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                    }

                    return new Tuple<string, string>(Convert.ToBase64String(memoryStream.ToArray()), Convert.ToBase64String(ivBytes));
                }
            }
        }


        public static string AesDecrypt(string key, string data, string iv)
        {
            byte[] cipherBytes = Convert.FromBase64String(data);
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] ivBytes = Convert.FromBase64String(iv);
            using (var aes = AesCryptoServiceProvider.Create())
            {
                // http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
                // https://stephenhaunts.com/2013/03/04/cryptography-in-net-advanced-encryption-standard-aes/
                aes.Mode = CipherMode.CBC;// default and recommended
                aes.Padding = PaddingMode.PKCS7; // default and recommended
                aes.KeySize = 256;

                var decryptor = aes.CreateDecryptor(keyBytes, ivBytes);

                using (var cipherMemoryStream = new MemoryStream(cipherBytes))
                {
                    using (var cryptoStream = new CryptoStream(cipherMemoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader s = new StreamReader(cryptoStream))
                        {
                            var buffer = new byte[cipherMemoryStream.Length];

                            var actualSize = cryptoStream.Read(buffer, 0, buffer.Length);

                            Array.Resize<byte>(ref buffer, actualSize);

                            return Encoding.UTF8.GetString(buffer).SubstringBefore("\0");
                        }
                    }

                }

            }
        }

    }
    public static class Extensions
    {
        public static string SubstringBefore(this string text, string find)
        {
            if (text.IndexOf(find) == -1)
            {
                throw new Exception($"\"{find}\" not found in \"{text}\"");
            }
            return text.Substring(0, text.IndexOf(find));
        }

        public static string SubstringAfter(this string text, string find)
        {
            if (text.IndexOf(find) == -1)
            {
                throw new Exception($"\"{find}\" not found in \"{text}\"");
            }
            return text.Substring(text.IndexOf(find) + find.Length);
        }
    }

}
