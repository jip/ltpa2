# ltpa2
LTPA2 cookie encryptor/decryptor/verifier

## Quick start

### Encrypt

```php
require 'ltpa2.php';

$sPassword               = '...';  // password to decrypt 3DES key and RSA key's material
$sSymKeyCiphertextB64    = '...';  // encrypted 3DES symmetric key in Base64 form
$sPrvKeyRawCiphertextB64 = '...';  // encrypted RSA private key's material in Base64 form

$sPlaintext = 'Text to encrypt';

$sCiphertextB64 = ltpa2\encrypt($sPlaintext, $sPassword, $sSymKeyCiphertextB64, $sPrvKeyRawCiphertextB64);
```

### Decrypt and verify

```php
require 'ltpa2.php';

$sPassword            = '...';  // password to decrypt 3DES key
$sSymKeyCiphertextB64 = '...';  // encrypted 3DES symmetric key in Base64 form
$sPubKeyRawB64        = '...';  // RSA public key's material in Base64 form

$sCiphertextB64       = '...';

$sPlaintextVerified = ltpa2\decrypt($sCiphertextB64, $sPassword, $sSymKeyCiphertextB64, $sPubKeyRawB64);
$bIsVerified = '' !== $sPlaintextVerified;
```

## Reconstruct WebSphere keys material from 3DES and RSA key

```console
$ ./mkkeys.sh > keys.properties
```

## Self testing

```console
$ php ltpa2-test-1.php
original plaintext: '...'
encryption test passed
original ciphertext: '...'
decryption test passed

$ ./mkkeys.sh ltpa2-test-2-passwd.txt ltpa2-test-2-3des-key.bin ltpa2-test-2-rsa-key.pem | cmp keys.properties && echo Succeed || echo Failed
Succeed

$ php asn1-test-1.php > asn1-test-1.out.der
$ openssl asn1parse -i -dump -inform der -in asn1-test-1.out.der > asn1-test-1.out.asn1
$ xxd -d -p asn1-test-1.out.der > asn1-test-1.out.xxd
$ openssl rsa -in asn1-test-1.out.der -inform der -text -noout > asn1-test-1.out.dump

$ php asn1-test-2.php > asn1-test-2.out.der
$ openssl asn1parse -i -dump -inform der -in asn1-test-2.out.der > asn1-test-2.out.asn1
$ xxd -d -p asn1-test-2.out.der > asn1-test-2.out.xxd

$ php asn1-test-3.php > asn1-test-3.out.der
$ openssl asn1parse -i -dump -inform der -in asn1-test-3.out.der > asn1-test-3.out.asn1
$ xxd -d -p asn1-test-3.out.der > asn1-test-3.out.xxd
$ openssl rsa -in asn1-test-3.out.der -inform der -pubin -text -noout > asn1-test-3.out.dump
```

## Requirements

- PHP 7+
