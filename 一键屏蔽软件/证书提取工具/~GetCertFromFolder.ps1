$exportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
foreach ($exeFile in (ls *.exe).Name) {
    $cert = (Get-AuthenticodeSignature $exeFile).SignerCertificate
    if ($cert -ne $null) {
        $hashStr = $cert.GetCertHashString()
        $hashAlgo = $cert.SignatureAlgorithm.FriendlyName
        $issueTo = ($cert.SubjectName.Format($true).Split([Environment]::NewLine) | where {$_.StartsWith("CN=")}).Substring(3)
        $validTo = $cert.NotAfter.ToString("yyyy-MM-dd")

        $outputFileName = ([char[]]"$hashStr - $hashAlgo - $issueTo - $validTo.cer" | where {[IO.Path]::InvalidPathChars -notcontains $_}) -join ''
        $outputPath = Join-Path -Path (pwd).Path -ChildPath $outputFileName
        [IO.File]::WriteAllBytes($outputPath, $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    }
}