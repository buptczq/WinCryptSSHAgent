# Yubikey on WSL

This tutorial will guide you to confgure YubiKey so it can be used with SSH under WSL. We will use YubiKey as a PIV Compatible Smart Card. Note that YubiKey also has other modes that can be used for secure SHH access like GPG that are not covered in this tutorial.

## Prerequisites

* Fresh YubiKey 5 
* Yubico software from https://www.yubico.com/products/services-software/download/smart-card-drivers-tools/
  * YubiKey Manager (graphic interface) - it also installs `ykman.exe`
  * YubiKey Smart Card Minidriver (Windows) - it is required to get ECDSA instead of default RSA
* WinCrypt SSH Agent from https://github.com/buptczq/WinCryptSSHAgent
* Console (ie. `cmd.exe` or Windows Terminal)

## Steps

### Insert YubiKey into USB port of your computer
   
You can check with Device Manager (`devmgmt.msc`) that the system recognized your key. It will be listed under *Smart Cards* as *YubiKey Smart Card Minidriver*.

### Change default PIN and PUK

Execute following commands, provide new PIN and PUK when prompted:

1. `"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv set-pin-retries 5 10`
1. `"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv change-pin --pin 123456`
1. `"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv change-puk --puk 12345678`
1. `"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv change-management-key --generate --protect --touch`

  This will give you a YubiKey with PIN and PUK that is only known to you and requires touch to change keys on it.

### Generate Keys

1. `"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv generate-key --algorithm ECCP384 --format PEM --pin-policy ONCE --touch-policy ALWAYS 9a "%UserProfile%\Desktop\%username%_public_key.pem"`

    Command generates private key inside of YubiKey. It is not possible to extract it so it is very secure. Also it requires a touch every time it is used for authentication.

1. `"C:\Program Files\Yubico\YubiKey Manager\ykman.exe" piv generate-certificate --valid-days 365 --subject "SSH Key" 9a "%UserProfile%\Desktop\%username%_public_key.pem"`

    Command generates a certificate from your public key. In brief: Windows needs it when speaking to your YubiKey.

### Check Windows Certificate Store 

 1. Unplug your YubiKey.
 1. Plug your YubiKey back.
 1. Run Certificate Manager Tool (`certmgr.msc`) and in *Certificates - Current User \ Personal \ Certificates* your certificate named **SSH key** should be visible.

### Confiure YubiKey for SSH in WLS and target machine

1. Ensure that `WinCryptSSHAgent.exe` is running.
1. Right click on *WinCrypt SSH Agent*'s icon in tray and select *Show WSL settings* then press OK.

    Line like `export SSH_AUTH_SOCK=/mnt/c/Users/Jane/wincrypt-wsl.sock` will be copeid into your clipboard.

1. Run your WSL console and execute command from previosu step.
1. `ssh` into your target machine, authenticate with credentials used until now.
1. Right click on *WinCrypt SSH Agent*'s icon in tray and select *Show public keys settings* then press OK.

    All known keys in SSH format will be copied. You need to locate one named **SHA key**.

1. Copy line with *SSH key* into `~\.ssh\authorized_keys` on target machine.
1. Disconnect from target machine.

### Use YubiKey for SSH

1. `ssh` into your machine.
1. Provide PIN when Windows asks.
1. Touch YubiKey twice (it should be blinking).
1. You should be allowed into your target machine. Enjoy! :rocket:




