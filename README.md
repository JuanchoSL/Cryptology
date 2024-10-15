# Description

This library brings together different reversible encryption systems, keeping the parameterization unified with the idea of ​​being able to change systems without maintenance in the code, simply adapting the constructions of the instances

# Instalation

use composer in order to install it

```bash
composer require juanchosl\cryptology
```

# Types

## Open SSL

### Symmetric Password
The same password in plain text format for encode and decode, all receivers need to know the password

#### Options
- cipher: a cipher algorithm available, can check the response from openssl_get_cipher_methods()

#### Examples
```php
$crypter = new Password;
$crypter->setPassword('myPassword');
$crypted_message = $crypter->encrypt('A message to encrypt');

$decrypter = new Password;
$decrypter->setPassword('myPassword');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

### Asymmetric PrivateKey/PublicKey

One to one, if the sender encode using the privatekey, the receiver needs to decode using the related public key

#### Options
- padding: OPENSSL_PKCS1_PADDING or OPENSSL_NO_PADDING

#### Examples
```php
$crypter = new PrivateKey;
$crypter->setPrivateKey('/path/to/private_key.key');
$crypted_message = $crypter->encrypt('A message to encrypt');

$decrypter = new PublicKey;
$decrypter->setPublicKey('/path/to/public_key.pub');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

### Pkcs1
For all message types, send to some using public keys but generating an exclusive passphrase for each receiver, any one need to decode using his private key and the passphrase of the message

#### Options
- cipher: a cipher algorithm available, can check the response from openssl_get_cipher_methods()
- algo: an algorithm method available, can check the response from openssl_get_md_methods()

#### Examples
```php
$crypter = new Pkcs1;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypted_message = $crypter->encrypt('A message to encrypt');//An array with the crypted message in first position and an array with the passphrases as second element of the response

$decrypter = new Pkcs1;
$decrypter->setPrivateKey('/path/to/my/private_key.key');
$decrypter->setPublicKey('/path/to/public_key.pub');
$decrypter->setPassword('message_password');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

You can sign the sended message with your own private key in order to ensure your identity
```php
$crypter = new Pkcs1;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypter->setPrivateKey('/path/to/my/private_key.key');
$signed_message = $crypter->sign('A message to sign');
```
And verify the received message using the sender certificate
```php
$decrypter = new Pkcs1;
$decrypter->setRemotes(['/path/to/sender/certificate.crt']);
$message = $decrypter->verify($signed_message);
```

### Pkcs7

For SMIME messages, send to some using receivers certificates and decode using the private key. We can sign the messages in order to apply a certification of sender

#### Options
- cipher: a cipher constant from openssl, by default OPENSSL_CIPHER_AES_256_CBC

#### Examples
```php
$crypter = new Pkcs7;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypted_message = $crypter->encrypt('A message to encrypt');

$decrypter = new Pkcs7;
$decrypter->setPrivateKey('/path/to/my/private_key.key');
$decrypter->setCertificate('/path/to/my/certificate.crt');
$decrypter->setRemotes(['/path/to/sender/certificate.crt']);
$decrypted_message = $decrypter->decrypt($crypted_message);
```

You can sign the sended message with your own private key in order to ensure your identity
```php
$crypter = new Pkcs7;
$crypter->setPrivateKey('/path/to/my/private_key.key');
$crypter->setCertificate('/path/to/my/certificate.crt');
$signed_message = $crypter->sign('A message to encrypt');
```
And verify the received message using the sender certificate
```php
$decrypter = new Pkcs7;
$decrypter->setRemotes(['/path/to/sender/certificate.crt']);
$message = $decrypter->verify($signed_message);
```

### CMS
For multipurpose messages, send to some using receivers certificates and decode using our own private key and certificate. We can sign the messages in order to apply a certification of sender

#### Options
- encoding: OPENSSL_ENCODING_PEM, OPENSSL_ENCODING_SMIME or OPENSSL_ENCODING_DER (by default)
- cipher: a cipher constant from openssl, by default OPENSSL_CIPHER_AES_256_CBC

#### Examples
```php
$crypter = new Cms;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypted_message = $crypter->encrypt('A message to encrypt');//An array with the crypted message in first position and an array with the passphrases as second element of the response

$decrypter = new Cms;
$decrypter->setPrivateKey('/path/to/my/private_key.key');
$decrypter->setCertificate('/path/to/my/certificate.crt');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

You can sign the sended message with your own private key in order to ensure your identity
```php
$crypter = new Cms;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypter->setPrivateKey('/path/to/my/private_key.key');
$decrypter->setCertificate('/path/to/my/certificate.crt');
$signed_message = $crypter->sign('A message to sign');
```
And verify the received message using the sender certificate
```php
$decrypter = new Cms;
$decrypter->setRemotes(['/path/to/sender/certificate.crt']);
$message = $decrypter->verify($signed_message);
```

## Gpg

For use the Open GPG standard

### Gnupg
Require the gnupg library installed for php

#### Examples
```php
$crypter = new Gnupg;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypted_message = $crypter->encrypt('A message to encrypt');//An array with the crypted message in first position and an array with the passphrases as second element of the response

$decrypter = new Gnupg;
$decrypter->setPrivateKey('/path/to/my/private_key.key');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

You can sign the sended message with your own private key in order to ensure your identity
```php
$crypter = new Gnupg;
$crypter->setRemotes(['/path/to/receiver/certificate.crt']);
$crypter->setPrivateKey('/path/to/my/private_key.key');
$signed_message = $crypter->sign('A message to sign');
```
And verify the received message using the sender certificate
```php
$decrypter = new Gnupg;
$decrypter->setPrivateKey('/path/to/my/private_key.key');
$decrypter->setRemotes(['/path/to/sender/certificate.crt']);
$message = $decrypter->verify($signed_message);
```

### GpgConsole
Require the gpg library installed for console

#### Examples
```php
$crypter = new GpgConsole;
$crypter->setRemotes(['receiver_fingerprint']);
$crypted_message = $crypter->encrypt('A message to encrypt');//An array with the crypted message in first position and an array with the passphrases as second element of the response

$decrypter = new GpgConsole;
$decrypter->setPrivateKey('private_fingerprint');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

You can sign the sended message with your own private key in order to ensure your identity
```php
$crypter = new GpgConsole;
$crypter->setPrivateKey('private_fingerprint');
$crypter->setRemotes(['receiver_fingerprint']);
$signed_message = $crypter->sign('A message to sign');
```
And verify the received message using the sender certificate
```php
$decrypter = new GpgConsole;
$decrypter->setPrivateKey('private_fingerprint');
$decrypter->setRemotes(['sender_fingerprint']);
$message = $decrypter->verify($signed_message);
```

## Older systems

We add an older type of encryption in order to be able to mantain our systems

### Mcrypt

The same password in plain text format for encode and decode, all receivers need to know the password
```php
$crypter = new Mcrypt;
$crypter->setPassword('myPassword');
$crypted_message = $crypter->encrypt('A message to encrypt');

$decrypter = new Mcrypt;
$decrypter->setPassword('myPassword');
$decrypted_message = $decrypter->decrypt($crypted_message);
```

## Utils

For create a GPG key use the console and follow the instructions, updating the phpunit.xml with the new credentials
```bash
root@1be56db22035:/application# gpg --full-generate-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
  (14) Existing key from card
Your selection? 1
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072) 1024
Requested keysize is 1024 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 365
Key expires at Wed Oct 15 17:10:13 2025 UTC
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: Juan Sanchez
Email address: JuanchoSL@hotmail.com
Comment: Cryptology
You selected this USER-ID:
    "Juan Sanchez (Cryptology) <JuanchoSL@hotmail.com>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: directory '/root/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/root/.gnupg/openpgp-revocs.d/572A0A03F67FD96351BBF7F3FC869096CAF45839.rev'
public and secret key created and signed.

pub   rsa1024 2024-10-15 [SC] [expires: 2025-10-15]
      572A0A03F67FD96351BBF7F3FC869096CAF45839
uid                      Juan Sanchez (Cryptology) <JuanchoSL@hotmail.com>
sub   rsa1024 2024-10-15 [E] [expires: 2025-10-15]
```