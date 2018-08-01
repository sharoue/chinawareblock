//Code by EraserKing (https://github.com/EraserKing)
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;

namespace GetCertFromFolder
{
    public class Program
    {
        public static readonly string invalidChar = new string(Path.GetInvalidFileNameChars()) + new string(Path.GetInvalidPathChars());

        public static void Main(string[] args)
        {
            string baseFolder = @".";
            foreach (FileInfo fileInfo in new DirectoryInfo(baseFolder).EnumerateFiles("*.exe"))
            {
                try
                {
                    X509Certificate cert = X509Certificate.CreateFromSignedFile(fileInfo.FullName);
                    string certInBase64 = ExportToPEM(cert);

                    string hash = cert.GetCertHashString();
                    string issueTo = cert.Subject.Split(new string[] { ", " }, StringSplitOptions.None).FirstOrDefault(x => x.StartsWith("CN=")).Substring(3);
                    string validTo = DateTime.Parse(cert.GetExpirationDateString()).ToString("yyyy-MM-dd");
                    string certFileName = hash + "-" + issueTo + "-" + validTo + ".cer";

                    File.WriteAllText(Path.Combine(baseFolder, removeInvalidCharInPath(certFileName)), certInBase64);
                }
                catch (CryptographicException)
                {
                    continue;
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
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

    }
}
