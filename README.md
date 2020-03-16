# hush

####

hush is a minimalistic command line password manager.
It was developed to satisfy the need to manage passwords and other secrets so they can be stored securely in the text format, compatible with git and other version control. systems.
Hush does not require a master password as other password managers do, instead it uses RSA public/private key pair to encrypt and decrypt passwords. These are exactly same keys used for ssh connections to the github and similar.

#### What's new?

- Version 202003.4 (Mar 6, 2020)

  - introduced GCM mode for the AES encryption. Choose between GCM and EAX. For the secrets encrypted with the previous version explicitly pass `--mode eax` to decrypt.

- Version 202001.4 (Jan 23, 2020)

  - Improved compatibility with ssh RSA keys

- Version 202001.3 (Jan 18, 2020)

  - Initial stable release

### installation

hush requires Python 3.7 or newer installation; to install hush, execute:

```
pip3 install hush
```

or, depending on your python setup:

```
pip install hush
```

verify that hush is installed on your box by running:

```
hush --version
```

### sample usage

```
hush generate | hush encrypt > password.txt
```

The above will generate a random password, encrypt it, and store as a base64 string in the file `password.txt`. This can be checked in into git and so on.

To decrypt the password and store it on the clipbord, on the Mac use:

```
hush decrypt password.txt | pbcopy
```

The same thing can be achieved on Windows as:

```
push decrypt password.txt | clip
```

### configuration

You can pass the options through the command line parameters or use the configuration. `hush init` creates the default configuration, you will still need to provide the private and public RSA keys though. If you don't have them, you can run `hush keygen` to generate a pair.
