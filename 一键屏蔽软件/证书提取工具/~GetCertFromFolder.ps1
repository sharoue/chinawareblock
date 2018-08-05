$exportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
foreach ($exeName in (ls *.exe).BaseName) {
    $exeFile = $exeName + '.exe'
    $cert = (Get-AuthenticodeSignature $exeFile).SignerCertificate
	$hashstr = $cert.GetCertHashString()
	$hashalgo = $cert.SignatureAlgorithm.FriendlyName
	$issueto = $cert.subject.Substring($cert.subject.indexof("CN=")+3)
	$issueto = $issueto.Substring(0,$issueTo.IndexOf('='))
	$issueto = $issueto.Substring(0,$issueTo.LastIndexOf(','))
	$validto = $cert.GetExpirationDateString().split()[0].Replace('/','')
    if ($cert -ne $null) {
        $outputPath = (pwd).Path + '\' + $hashstr + ' - ' + $hashalgo + ' - ' + $issueto + ' - ' + $validto + '.cer'
        [System.IO.File]::WriteAllBytes($outputPath, $cert.Export($exportType))
    }
}