# hush

####

hush is a minimalistic command line password manager.
It was developed to satisfy the need to manage passwords and other secrets so they can be stored securely in the text format, compatible with git and onther version control. systems.
Hush does not require a master password as other password managers do, instead it uses RSA public/private key pair to encrypt and decrypt passwords. These are exactly same keys used for ssh connectons to the github and similar.

#### What's new?

- Version 0.5.2 (Jan 1, 2020)
<<<<<<< HEAD
  - repackage to allow cli-less usage
=======

  - repackage to allow cli-less usage

>>>>>>> master
- Version 0.5.1 (Dec 31, 2019)
  - support for generating RSA key pair
  - support for the private key passphrase, for extra security

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

hush requires to know where to find the private and public key files, these locations can be provided either as parameters or set as environment variables. For more options, run

```
hush --help
```
