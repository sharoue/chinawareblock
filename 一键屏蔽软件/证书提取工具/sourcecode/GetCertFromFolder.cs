using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GetCertFromFolder
{
    public class Program
    {
        public static readonly string invalidChar = new string(Path.GetInvalidFileNameChars()) + new string(Path.GetInvalidPathChars());

        public static void Main(string[] args)
        {
            string currentDirectory = Directory.GetCurrentDirectory();
            foreach (FileInfo fileInfo in new DirectoryInfo(currentDirectory).EnumerateFiles("*.exe"))
            {
                try
                {
                    X509Certificate2 cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(fileInfo.FullName));
                    string contents = Program.ExportToPEM(cert);
                    string certHashString = cert.GetCertHashString();
                    string friendlyName = cert.SignatureAlgorithm.FriendlyName;
                    string issueTo = cert.Subject.Split(new string[]
                    {
                        ", "
                    }, StringSplitOptions.None).FirstOrDefault((string x) => x.StartsWith("CN=")).Substring(3);
                    string validTo = cert.NotAfter.ToString("yyyy-MM-dd");
                    string path = string.Format("{0} - {1} - {2} - {3}.cer", new object[]
                    {
                        certHashString,
                        friendlyName,
                        issueTo,
                        validTo
                    });
                    File.WriteAllText(Path.Combine(currentDirectory, Program.removeInvalidCharInPath(path)), contents);
                }
                catch (CryptographicException)
                {
                }
            }
        }

        private static string removeInvalidCharInPath(string path)
        {
            foreach (char c in invalidChar)
            {
                path = path.Replace(c.ToString(), "");
            }
            return path;
        }

        private static string ExportToPEM(X509Certificate cert)
        {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            stringBuilder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            stringBuilder.AppendLine("-----END CERTIFICATE-----");
            return stringBuilder.ToString();
        }
    }
}



