# Using VS Code Git SSH
This will help get Git configured to work with the WinCryptSSHAgent provider to enable SSH-based authentication within Visual Studio Code.

## Prerequisites
* Configured YubiKey, SSH keys, etc.
    * Follow the tutorial in [WSL](wsl_tutorial.md) to get setup
* GitHub Account

## Steps
1. Insert YubiKey into computer
2. Open Git `bash` by navigating to Start > Git > Git Bash OR typing Git Bash and letting the OS find it for you
3. Right-click on WinCryptSSHAgent and select `Show Cygwin Settings` and press OK
4. Paste the results of the previous command into the Git `bash` window, press Enter.
5. Type `ssh-add -L` and locate the key associated with your YubiKey (If following the [WSL](wsl_tutorial.md) directions, it will begin with `ecdsa-sha2-nistp384` and end with `SSH Key`)
6. Highlight the key and copy it to your clipboard.
7. Follow the steps provided by GitHub [here](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) to add the key to your account.
8. Test the configuration by entering `ssh -T git@github.com` into the Terminal within VS Code. Your YubiKey should start blinking. A satisfactory result looks like: ```PS C:\code> ssh -T git@github.com
Hi username! You've successfully authenticated, but GitHub does not provide shell access.```
9. Your setup should be complete and you can `git clone` using SSH.

## Troubleshooting
* Depending on how many keys you have, you may run into issues with invalid authentication. Leverage SSH `config` files as [discussed here](https://serverfault.com/questions/906871/force-the-use-of-a-gpg-key-as-an-ssh-key-for-a-given-server) to tie a specific file to `github.com` as a host.