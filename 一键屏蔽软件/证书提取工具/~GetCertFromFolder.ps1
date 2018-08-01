# Coded by rewqazxv (https://github.com/rewqazxv)
$exportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
foreach ($exeName in (ls *.exe).BaseName) {
    $exeFile = $exeName + '.exe'
    $cert = (Get-AuthenticodeSignature $exeFile).SignerCertificate
    if ($cert -ne $null) {
        $outputPath = (pwd).Path + '\' + $cert.GetCertHashString() + '-' + $cert.SignatureAlgorithm.FriendlyName + '-' + $cert.GetExpirationDateString().split()[0].Replace('/','') + '.cer'
        [System.IO.File]::WriteAllBytes($outputPath, $cert.Export($exportType))
    }
}