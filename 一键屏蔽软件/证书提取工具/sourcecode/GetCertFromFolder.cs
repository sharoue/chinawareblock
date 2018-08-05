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

        public static readonly string exeName = Process.GetCurrentProcess().MainModule.FileName;

        public static void Main(string[] args)
        {
            string baseFolder = Directory.GetCurrentDirectory();
            foreach (FileInfo fileInfo in new DirectoryInfo(baseFolder).EnumerateFiles("*.exe").Where(x => !x.Equals(exeName)))
            {
                try
                {
                    X509Certificate2 cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(fileInfo.FullName));
                    string certInBase64 = ExportToPEM(cert);

                    string hash = cert.GetCertHashString();
                    string alth = cert.SignatureAlgorithm.FriendlyName;
                    string issueTo = cert.Subject.Substring(cert.Subject.IndexOf("CN=") + 3);
                    issueTo = issueTo.Substring(0, issueTo.IndexOf('='));
                    issueTo = issueTo.Substring(0, issueTo.LastIndexOf(','));
                    string validTo = cert.NotAfter.ToString("yyyy-MM-dd");
                    string certFileName = $"{hash} - {alth} - {issueTo} - {validTo}.cer";

                    File.WriteAllText(Path.Combine(baseFolder, RemoveInvalidCharInPath(certFileName)), certInBase64);
                }
                catch (CryptographicException)
                {
                    continue;
                }
            }
        }

        private static string RemoveInvalidCharInPath(string path)
        {
            foreach (char c in invalidChar)
            {
                path = path.Replace(c.ToString(), "");
            }
            return path;
        }

        private static string ExportToPEM(X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

    }
}