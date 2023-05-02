<?php
/**
 * LTPA2 cookie [1] encryptor/decryptor/verifier based on [2]
 * ver. 2.1.0
 * (c) 2017-02-06 zhuravlov.ip@ya.ru
 *
 * @see
 * [1] http://www.ibm.com/support/knowledgecenter/SS9H2Y_7.5.0/com.ibm.dp.doc/ltpa_versionsandtokenformats.html
 * [2] https://sites.google.com/site/samiraraujo/projects/ltpa-token-factory
 */

// === config ===

// prevent arguments type casting, force arguments and return values type checking
declare(strict_types = 1);

namespace ltpa2;

ini_set('display_errors', '1');
error_reporting(E_ALL | E_STRICT);

const DEBUG            = false;  // @var bool verbosity
const OPENSSL_B64_DATA = 0    ;  // @var int  to use as empty bitmask

require_once 'asn1.php';

// === interface ===

/**
 * encrypt token by password and encrypted key given
 *
 * @param  string $sLtpaPlaintext          LTPA2 token body plaintext in any of the following forms:
 *                                           token_body%expiration_time
 *                                         or
 *                                           token_body
 *                                         an expiration time if omitted will be restored from token_body,
 *                                         or, if not found there, will be set to the value:
 *                                           current_timestamp + 2 hours
 * @param  string $sPassword               password to decrypt keys supplied
 * @param  string $sSymKeyCiphertextB64    encrypted 3DES symmetric key in Base64 form
 * @param  string $sPrvKeyRawCiphertextB64 encrypted RSA private key's material in Base64 form
 * @return string                          encrypted signed LTPA2 token in Base64 form
 */
function encrypt(string $sLtpaPlaintext, string $sPassword, string $sSymKeyCiphertextB64, string $sPrvKeyRawCiphertextB64): string {
  DEBUG && printf("encrypt(): LTPA2 token plaintext [%u] == '%s'\n", strlen($sLtpaPlaintext), bin2str($sLtpaPlaintext));
  DEBUG && printf("encrypt(): password [%u] == '%s'\n", strlen($sPassword), bin2str($sPassword));
  DEBUG && printf("encrypt(): 3DES symmetric key ciphertext Base64 [%u] == '%s'\n", strlen($sSymKeyCiphertextB64), $sSymKeyCiphertextB64);
  DEBUG && printf("encrypt(): RSA private key's material ciphertext Base64 [%u] == '%s'\n", strlen($sPrvKeyRawCiphertextB64), $sPrvKeyRawCiphertextB64);

  list($sLtpaPlaintextBody, $sLtpaPlaintextExpire) = parseInput($sLtpaPlaintext);
  DEBUG && printf("encrypt(): LTPA2 token body [%u] == '%s'\n", strlen($sLtpaPlaintextBody), $sLtpaPlaintextBody);
  DEBUG && printf("encrypt(): LTPA2 token expire [%u] == '%s'\n", strlen($sLtpaPlaintextExpire), $sLtpaPlaintextExpire);
  // sha1(token_body)
  $sDigest20 = sha1($sLtpaPlaintextBody, true);
  DEBUG && printf("encrypt(): LTPA2 token body digest SHA-1 [%u] == '%s'\n", strlen($sDigest20), bin2str($sDigest20));
  // signature(sha1(token_body))
  $sDigest20Signature = sign($sDigest20, $sPassword, $sPrvKeyRawCiphertextB64);
  DEBUG && printf("encrypt(): LTPA2 token signature [%u] == '%s'\n", strlen($sDigest20Signature), bin2str($sDigest20Signature));
  // token := token_body%expiration_time%base64(signature(sha1(token_body)))
  $sLtpaToken = $sLtpaPlaintextBody . '%' . $sLtpaPlaintextExpire . '%' . base64_encode($sDigest20Signature);
  DEBUG && printf("encrypt(): LTPA2 token plaintext [%u] == '%s'\n", strlen($sLtpaToken), bin2str($sLtpaToken));
  DEBUG && printf("encrypt(): LTPA2 token plaintext [%u] == '%s'\n", strlen($sLtpaToken), $sLtpaToken);
  // crypt LTPA2 token by 3DES symmetric key and then apply a base64 encoding
  // - get 3DES symmetric key
  $sSymKey = get3DESKey($sSymKeyCiphertextB64, $sPassword);
  $sSymKey !== false && (DEBUG && printf("encrypt(): 3DES symmetric key plaintext [%u] == '%s'\n", strlen($sSymKey), bin2str($sSymKey)) || true) || exit('encrypt(): openssl_decrypt() failed: '.openssl_error_string()."\n");
  $sSecretKey16 = substr($sSymKey, 0, 16);
  DEBUG && printf("encrypt(): trimmed 3DES symmetric key plaintext [%u] == '%s'\n", strlen($sSecretKey16), bin2str($sSecretKey16));
  $sIV16 = substr($sSymKey, 0, 16);
  DEBUG && printf("encrypt(): IV [%u] == '%s'\n", strlen($sIV16), bin2str($sIV16));
  // - encrypt LTPA2 token by 3DES symmetric key
  $sLtpaCiphertext = openssl_encrypt($sLtpaToken, 'aes-128-cbc', $sSecretKey16, OPENSSL_RAW_DATA, $sIV16);  // AES/CBC/PKCS5Padding
  $sLtpaCiphertext !== false && (DEBUG && printf("encrypt(): LTPA2 token ciphertext [%u] == '%s'\n", strlen($sLtpaCiphertext), bin2str($sLtpaCiphertext)) || true) || exit('encrypt(): openssl_encrypt() failed: '.openssl_error_string()."\n");
  // - post-process LTPA2 token by base64
  $sLtpaCiphertextB64 = base64_encode($sLtpaCiphertext);
  DEBUG && printf("encrypt(): LTPA2 token ciphertext Base64 [%u] == '%s'\n", strlen($sLtpaCiphertextB64), $sLtpaCiphertextB64);
  return $sLtpaCiphertextB64;
}

/**
 * decrypt and verify token by password and encrypted key given
 *
 * @param  string $sLtpaCiphertext      encrypted LTPA2 token in Base64 form
 * @param  string $sPassword            password to decrypt 3DES key supplied
 * @param  string $sSymKeyCiphertextB64 encrypted 3DES symmetric key in Base64 form
 * @param  string $sPubKeyRawB64        RSA public key's material in Base64 form
 * @return string                       verified LTPA2 token body plaintext
 */
function decrypt(string $sLtpaCiphertextB64, string $sPassword, string $sSymKeyCiphertextB64, string $sPubKeyRawB64): string {
  DEBUG && printf("decrypt(): LTPA2 token ciphertext [%u] == '%s'\n", strlen($sLtpaCiphertextB64), $sLtpaCiphertextB64);
  DEBUG && printf("decrypt(): password [%u] == '%s'\n", strlen($sPassword), bin2str($sPassword));
  DEBUG && printf("decrypt(): 3DES symmetric key ciphertext Base64 [%u] == '%s'\n", strlen($sSymKeyCiphertextB64), $sSymKeyCiphertextB64);
  DEBUG && printf("decrypt(): RSA public key's material Base64 [%u] == '%s'\n", strlen($sPubKeyRawB64), $sPubKeyRawB64);

  // - get 3DES symmetric key
  $sSymKey = get3DESKey($sSymKeyCiphertextB64, $sPassword);
  $sSymKey !== false && (DEBUG && printf("decrypt(): 3DES symmetric key plaintext [%u] == '%s'\n", strlen($sSymKey), bin2str($sSymKey)) || true) || exit('decrypt(): openssl_decrypt() failed: '.openssl_error_string()."\n");
  $sSecretKey16 = substr($sSymKey, 0, 16);
  DEBUG && printf("decrypt(): trimmed 3DES symmetric key [%u] == '%s'\n", strlen($sSecretKey16), bin2str($sSecretKey16));
  $sIV16 = substr($sSymKey, 0, 16);
  DEBUG && printf("decrypt(): IV [%u] == '%s'\n", strlen($sIV16), bin2str($sIV16));
  // decrypt LTPA2 token by 3DES symmetric key
  $sLtpaPlaintext = openssl_decrypt($sLtpaCiphertextB64, 'aes-128-cbc', $sSecretKey16, OPENSSL_B64_DATA, $sIV16);  // AES/CBC/PKCS5Padding
  DEBUG && ($sLtpaPlaintext !== false && printf("decrypt(): LTPA2 token plaintext [%u] == '%s'\n", strlen($sLtpaPlaintext), $sLtpaPlaintext) || printf("decrypt(): openssl_decrypt() failed\n"));
  $aLtpaPlaintext = explode('%', $sLtpaPlaintext, 3);
  count($aLtpaPlaintext) == 3 || exit("decrypt(): broken LTPA2 plaintext format: '$sLtpaPlaintext'\n");
  list($sLtpaPlaintextBody, $sLtpaPlaintextExpire, $sDigest20SignatureB64) = $aLtpaPlaintext;
  DEBUG && printf("decrypt(): LTPA2 token body [%u] == '%s'\n", strlen($sLtpaPlaintextBody), $sLtpaPlaintextBody);
  DEBUG && printf("decrypt(): LTPA2 token expire [%u] == '%s'\n", strlen($sLtpaPlaintextExpire), $sLtpaPlaintextExpire);
  DEBUG && printf("decrypt(): LTPA2 token signature Base64 [%u] == '%s'\n", strlen($sDigest20SignatureB64), $sDigest20SignatureB64);
  $sDigest20Signature = base64_decode($sDigest20SignatureB64);
  DEBUG && printf("decrypt(): LTPA2 token signature [%u] == '%s'\n", strlen($sDigest20Signature), bin2str($sDigest20Signature));
  // verify signature
  $sDigest20 = sha1($sLtpaPlaintextBody, true);
  DEBUG && printf("decrypt(): LTPA2 token body digest SHA-1 [%u] == '%s'\n", strlen($sDigest20), bin2str($sDigest20));
  $bVerified = verify($sDigest20, $sDigest20Signature, $sPubKeyRawB64);
  DEBUG && printf("decrypt(): verify() result == %s\n", $bVerified ? 'true' : 'false');
  // return verified LTPA2 token body plaintext or ''
  return $bVerified ? $sLtpaPlaintextBody . '%' . $sLtpaPlaintextExpire : '';
}

/** read, check, filter and post-process config file */
function readConfig(string $sConfigFilename): array {
  $fCheck = static function ($sKey) {
    static $aPropNames = ['com.ibm.websphere.ltpa.3DESKey', 'com.ibm.websphere.ltpa.PrivateKey', 'com.ibm.websphere.ltpa.PublicKey'];
    return in_array($sKey, $aPropNames, true);
  };
  $fUnEsc = static function ($sVal) {return str_replace('\=', '=', $sVal);};

  file_exists($sConfigFilename) || exit("readConfig(): config file '$sConfigFilename' not found\n");
  $aConfig = parse_ini_file($sConfigFilename, false, INI_SCANNER_RAW);
  is_array($aConfig) || exit("readConfig(): config file '$sConfigFilename' format is broken\n");

  return array_map($fUnEsc, array_filter($aConfig, $fCheck, ARRAY_FILTER_USE_KEY));
}

// === local functions ===

/** extract data from LTPA2 token plaintext, derive expiration time if omitted */
function parseInput(string $sInput): array {
  $aLtpaPlaintext = explode('%', $sInput, 2);  // form array either [0=>token_body] or [0=>token_body, 1=>expiration_time]
  if(count($aLtpaPlaintext) == 1) {
    // expiration time is absent in token's plaintext, let's look for it in the token body
    $aMatches = [];
    if(preg_match('/(^|\$)expire:(\d{13})($|\$)/', $aLtpaPlaintext[0], $aMatches) == 1) {
      // expiration time is found in token body
      $aLtpaPlaintext[1] = $aMatches[2];
    } else {
      // expiration time will be set as current time + 2 hours (IBM convention)
      $aLtpaPlaintext[1] = (string) (time() + 2*60*60) * 1000;
    }
  } elseif(count($aLtpaPlaintext) == 2 && preg_match('/^\d{13}$/', $aLtpaPlaintext[1]) == 1) {
    // expiration time is located in token's plaintext, use it, so NOP
  } else {
    exit("parseInput(): broken LTPA2 plaintext format: '$sInput'\n");
  }
  return $aLtpaPlaintext;
}

/** sign message; used by encrypt */
function sign(string $sMessage, string $sPassword, string $sPrvKeyRawCiphertextB64): string {
  $sPrvKeyRaw = get3DESKey($sPrvKeyRawCiphertextB64, $sPassword);
  $sPrvKeyRaw !== false && (DEBUG && printf("sign(): RSA Private key's material [%u] == '%s'\n", strlen($sPrvKeyRaw), bin2str($sPrvKeyRaw)) || true) || exit('sign(): openssl_decrypt() failed: '.openssl_error_string()."\n");
  $rPrvKey = getRSAPrvKey($sPrvKeyRaw);
  (PHP_MAJOR_VERSION < 8 ? is_resource($rPrvKey) && get_resource_type($rPrvKey) === 'OpenSSL key' : is_a($rPrvKey,'OpenSSLAsymmetricKey')) && (DEBUG && printf("sign(): RSA Private key created\n") || true) || exit('sign(): openssl_pkey_get_private() failed: '.openssl_error_string()."\n");
  $Signature = '';
  DEBUG && printf("sign(): message to sign [%u] == '%s'\n", strlen($sMessage), bin2str($sMessage));
  DEBUG && (($aPrvKeyDetails = openssl_pkey_get_details($rPrvKey)) && array_walk($aPrvKeyDetails['rsa'], function (&$v) {$v = bin2hex($v);}) && printf("sign(): openssl_pkey_get_details(rPrvKey) == '%s'\n", var_export($aPrvKeyDetails,true)));
  DEBUG && ($bRC = openssl_pkey_export($rPrvKey, $sPrvKey));
  DEBUG && ($bRC && printf("sign(): openssl_pkey_export(rPrvKey) == '%s'\n", $sPrvKey) || printf("sign(): openssl_pkey_export(rPrvKey) failed: %s\n", openssl_error_string()));
  $bRC = openssl_sign($sMessage, $Signature, $rPrvKey, OPENSSL_ALGO_SHA1);  // the same as 'sha1WithRSAEncryption'
  DEBUG && printf("sign(): openssl_sign() result == %s\n", $bRC ? 'succeed' : 'failed: '.openssl_error_string());
  DEBUG && printf("sign(): signature [%u] == '%s'\n", strlen($Signature), bin2str($Signature));
  PHP_MAJOR_VERSION < 8 && openssl_pkey_free($rPrvKey);
  DEBUG && printf("sign(): RSA private key destroyed\n");
  return $Signature;
}

/** verify message; used by decrypt */
function verify(string $sMessage, string $sSignature, string $sPubKeyRawB64): bool {
  $rPubKey = getPubKey($sPubKeyRawB64);
  (PHP_MAJOR_VERSION < 8 ? is_resource($rPubKey) && get_resource_type($rPubKey) === 'OpenSSL key' : is_a($rPubKey,'OpenSSLAsymmetricKey')) && (DEBUG && printf("verify(): X.509 Public key created\n") || true) || exit('verify(): openssl_pkey_get_public() failed: '.openssl_error_string()."\n");
  DEBUG && printf("verify(): message to verify [%u] == '%s'\n", strlen($sMessage), bin2str($sMessage));
  DEBUG && printf("verify(): signature [%u] == '%s'\n", strlen($sSignature), bin2str($sSignature));
  DEBUG && (($aPubKeyDetails = openssl_pkey_get_details($rPubKey)) && array_walk($aPubKeyDetails['rsa'], function (&$v) {$v = bin2hex($v);}) && printf("verify(): openssl_pkey_get_details(rPubKey) == '%s'\n", var_export($aPubKeyDetails,true)));
  $iRC = openssl_verify($sMessage, $sSignature, $rPubKey, OPENSSL_ALGO_SHA1);  // the same as 'sha1WithRSAEncryption'
  DEBUG && printf("verify(): openssl_verify() result == %s\n", $iRC == 1 ? 'succeed' : ($iRC == 0 ? 'failed' : 'error: '.openssl_error_string()));
  PHP_MAJOR_VERSION < 8 && openssl_free_key($rPubKey);
  DEBUG && printf("verify(): RSA public key destroyed\n");
  return $iRC == 1;
}

/** Decrypt 3DES symmetric key using a DESede/ECB/PKCS5Padding algorithm */
function get3DESKey(string $sSymKeyCiphertextB64, string $sPassword): string {
  // to do parity adjustment using bit in position 8 as the parity bit, instead of implementing
  // - java.lang.Integer.bitCount()
  // - com.sun.crypto.provider.DESKeyGenerator.setParityBit()
  // we use direct byte-to-byte translator strtr() with recode tables below, where non-changing pairs are omitted
  static $sAscii =
    "\x00\x03\x05\x06\x09\x0a\x0c\x0f\x11\x12\x14\x17\x18\x1b\x1d\x1e\x21\x22\x24\x27\x28\x2b\x2d\x2e\x30\x33\x35\x36\x39\x3a\x3c\x3f".
    "\x41\x42\x44\x47\x48\x4b\x4d\x4e\x50\x53\x55\x56\x59\x5a\x5c\x5f\x60\x63\x65\x66\x69\x6a\x6c\x6f\x71\x72\x74\x77\x78\x7b\x7d\x7e".
    "\x81\x82\x84\x87\x88\x8b\x8d\x8e\x90\x93\x95\x96\x99\x9a\x9c\x9f\xa0\xa3\xa5\xa6\xa9\xaa\xac\xaf\xb1\xb2\xb4\xb7\xb8\xbb\xbd\xbe".
    "\xc0\xc3\xc5\xc6\xc9\xca\xcc\xcf\xd1\xd2\xd4\xd7\xd8\xdb\xdd\xde\xe1\xe2\xe4\xe7\xe8\xeb\xed\xee\xf0\xf3\xf5\xf6\xf9\xfa\xfc\xff";
  static $sAsciiWithParity =
    "\x01\x02\x04\x07\x08\x0b\x0d\x0e\x10\x13\x15\x16\x19\x1a\x1c\x1f\x20\x23\x25\x26\x29\x2a\x2c\x2f\x31\x32\x34\x37\x38\x3b\x3d\x3e".
    "\x40\x43\x45\x46\x49\x4a\x4c\x4f\x51\x52\x54\x57\x58\x5b\x5d\x5e\x61\x62\x64\x67\x68\x6b\x6d\x6e\x70\x73\x75\x76\x79\x7a\x7c\x7f".
    "\x80\x83\x85\x86\x89\x8a\x8c\x8f\x91\x92\x94\x97\x98\x9b\x9d\x9e\xa1\xa2\xa4\xa7\xa8\xab\xad\xae\xb0\xb3\xb5\xb6\xb9\xba\xbc\xbf".
    "\xc1\xc2\xc4\xc7\xc8\xcb\xcd\xce\xd0\xd3\xd5\xd6\xd9\xda\xdc\xdf\xe0\xe3\xe5\xe6\xe9\xea\xec\xef\xf1\xf2\xf4\xf7\xf8\xfb\xfd\xfe";

  $sDigest20 = sha1($sPassword, true);
  DEBUG && printf("get3DESKey(): password digest SHA-1 [%u] == '%s'\n", strlen($sDigest20), bin2str($sDigest20));
  $sDigest24 = str_pad($sDigest20, 24, chr(0));
  DEBUG && printf("get3DESKey(): padded digest [%u] == '%s'\n", strlen($sDigest24), bin2str($sDigest24));
  $sSecretKey24 = strtr($sDigest24, $sAscii, $sAsciiWithParity);
  DEBUG && printf("get3DESKey(): padded digest with parity adjusted [%u] == '%s'\n", strlen($sSecretKey24), bin2str($sSecretKey24));

  return openssl_decrypt($sSymKeyCiphertextB64, 'des-ede3', $sSecretKey24, OPENSSL_B64_DATA);
}

/**
 * Reconstruct PKCS#1 RSA private key from key material. Key material comes from IBM WebSphere's
 * config file and is either a quintet (len(d),d,e,p,q) or a triplet (e,p,q).
 *
 * @note openssl_sign() accepts both PKCS#1 RSA and PKCS#8 private key formats
 */
function getRSAPrvKey(string $sPrvKeyRaw) {
  // we are going to compose the following structure:
  //   RSAPrivateKey ::= SEQUENCE {
  //     version           Version,                  // [0] 0 if two factors, 1 if more than two
  //     modulus           INTEGER,                  // [1] n := p*q
  //     publicExponent    INTEGER,                  // [2] e
  //     privateExponent   INTEGER,                  // [3] d := (p-1)*(q-1)/e
  //     prime1            INTEGER,                  // [4] p
  //     prime2            INTEGER,                  // [5] q
  //     exponent1         INTEGER,                  // [6] dP := d mod (p-1)
  //     exponent2         INTEGER,                  // [7] dQ := d mod (q-1)
  //     coefficient       INTEGER,                  // [8] qInv := (q^-1) mod p
  //     otherPrimeInfos   OtherPrimeInfos OPTIONAL  // [9]
  //   }
  // according to:
  // - RFC 2313 https://www.ietf.org/rfc/rfc2313.txt
  // - ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.asn
  static $iPrvKeyELen = 3 ;  // public exponent "e" length (bytes)
  static $iPrvKeyPLen = 65;  // 1st factor "p" length (bytes)
  static $iPrvKeyQLen = 65;  // 2nd factor "q" length (bytes)

  if(strlen($sPrvKeyRaw) > $iPrvKeyELen + $iPrvKeyPLen + $iPrvKeyQLen) {
    $iPrvKeyDLen = unpack("N", $sPrvKeyRaw)[1];  // read from first 4 bytes into unsigned long 32 bit, big endian byte order
    DEBUG && printf("getRSAPrvKey(): iPrvKeyDLen == %u\n", $iPrvKeyDLen);
    $aLtpaPrvKey[3] = substr($sPrvKeyRaw, 4                                             , $iPrvKeyDLen);  // d
    $aLtpaPrvKey[2] = substr($sPrvKeyRaw, 4 + $iPrvKeyDLen                              , $iPrvKeyELen);  // e
    $aLtpaPrvKey[4] = substr($sPrvKeyRaw, 4 + $iPrvKeyDLen + $iPrvKeyELen               , $iPrvKeyPLen);  // p
    $aLtpaPrvKey[5] = substr($sPrvKeyRaw, 4 + $iPrvKeyDLen + $iPrvKeyELen + $iPrvKeyPLen, $iPrvKeyQLen);  // q
  } else {
    $aLtpaPrvKey[2] = substr($sPrvKeyRaw, 0                                             , $iPrvKeyELen);  // e
    $aLtpaPrvKey[4] = substr($sPrvKeyRaw, $iPrvKeyELen                                  , $iPrvKeyPLen);  // p
    $aLtpaPrvKey[5] = substr($sPrvKeyRaw, $iPrvKeyELen + $iPrvKeyPLen                   , $iPrvKeyQLen);  // q
  }
  DEBUG && array_walk($aLtpaPrvKey, function ($sVal, $iKey) {printf("getRSAPrvKey(): preliminary aLtpaPrvKey[%d] [%u] == '%s'\n", $iKey, strlen($sVal), bin2str($sVal));});
  // compose RSA Private raw key
  $aRSAPrvKey = array_map(function($sUInt) {return gmp_import($sUInt);}, $aLtpaPrvKey);
  DEBUG && array_walk($aRSAPrvKey, function ($gInt, $iKey) {printf("getRSAPrvKey(): preliminary aRSAPrvKey[%d] == '%s'\n", $iKey, gmp_strval($gInt, -16));});
  $aRSAPrvKey[0] = 0;  // Version
  if($aRSAPrvKey[4] < $aRSAPrvKey[5]) {
    swap($aRSAPrvKey[4], $aRSAPrvKey[5]);
  }
  $aRSAPrvKey[1] = gmp_mul($aRSAPrvKey[4], $aRSAPrvKey[5]);  // n
  if(! isset($aRSAPrvKey[3])) {
    $aRSAPrvKey[3] = gmp_invert($aRSAPrvKey[2], gmp_mul(gmp_sub($aRSAPrvKey[4], 1), gmp_sub($aRSAPrvKey[5], 1)));  // d
  }
  if(! isset($aRSAPrvKey[6])) {
    $aRSAPrvKey[6] = gmp_div_r($aRSAPrvKey[3], gmp_sub($aRSAPrvKey[4], 1));  // dP
  }
  if(! isset($aRSAPrvKey[7])) {
    $aRSAPrvKey[7] = gmp_div_r($aRSAPrvKey[3], gmp_sub($aRSAPrvKey[5], 1));  // dQ
  }
  $aRSAPrvKey[8] = gmp_invert($aRSAPrvKey[5], $aRSAPrvKey[4]);  // qInv
  DEBUG && array_walk($aRSAPrvKey, function ($gInt, $iKey) {printf("getRSAPrvKey(): final aRSAPrvKey[%d] == '%s'\n", $iKey, gmp_strval($gInt, -16));});
  // encode to DER ASN.1 PKCS#1 RSA private key
  $sRSAPrvKeyDER = \asn1\encode([
    't' => \asn1\TYPE_SEQUENCE,
    'v' => array_map(function($v) {return ['t' => \asn1\TYPE_INTEGER, 'v' => $v];}, $aRSAPrvKey)
  ]);
  DEBUG && printf("getRSAPrvKey(): sRSAPrvKeyDER [%u] == '%s'\n", strlen($sRSAPrvKeyDER), bin2hex($sRSAPrvKeyDER));
  // encode to PEM
  $sRSAPrvKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n".base64_encode($sRSAPrvKeyDER)."\n-----END RSA PRIVATE KEY-----\n";
  DEBUG && printf("getRSAPrvKey(): sRSAPrvKeyPEM [%u] == '%s'\n", strlen($sRSAPrvKeyPEM), $sRSAPrvKeyPEM);
  // convert to PHP resource
  return openssl_pkey_get_private($sRSAPrvKeyPEM);
}

/**
 * Reconstruct public key from key material. Key material
 * comes from IBM WebSphere's config file and is a pair (n,e).
 *
 * @note openssl_verify() requires PKCS#8 X.509, not PKCS#1 RSA public key format
 */
function getPubKey(string $sPubKeyRawB64) {
  // we are going to compose the following structure:
  //   PublicKeyInfo ::= SEQUENCE {
  //     algorithm      AlgorithmIdentifier,               // see below
  //     RSAPublicKey   BIT STRING                         // see below
  //   }
  //
  //   AlgorithmIdentifier ::= SEQUENCE {
  //     algorithm      OBJECT IDENTIFIER,                 // 1.2.840.113549.1.1.1 (RFC 3279, 4055)
  //     parameters     ANY DEFINED BY algorithm OPTIONAL  // NULL
  //   }
  //
  //   RSAPublicKey ::= SEQUENCE {                         // RFC 4055
  //     modulus        INTEGER,                           // [0] n := p*q
  //     publicExponent INTEGER                            // [1] e
  //   }
  static $iPubKeyNLen = 129;  // modulus "n" length (bytes)
  static $iPubKeyELen =   3;  // public exponent "e" length (bytes)

  $sPubKeyRaw = base64_decode($sPubKeyRawB64);
  $sPubKeyRaw !== false && (DEBUG && printf("getPubKey(): RSA public key's material [%u] == '%s'\n", strlen($sPubKeyRaw), bin2str($sPubKeyRaw)) || true) || exit("getPubKey(): base64_decode() failed\n");
  $aLtpaPubKey[0] = substr($sPubKeyRaw, 0           , $iPubKeyNLen);  // n
  $aLtpaPubKey[1] = substr($sPubKeyRaw, $iPubKeyNLen, $iPubKeyELen);  // e
  DEBUG && array_walk($aLtpaPubKey, function ($sVal, $iKey) {printf("getPubKey(): final aLtpaPubKey[%d] [%u] == '%s'\n", $iKey, strlen($sVal), bin2str($sVal));});
  // compose RSA Public raw key
  $aRSAPubKey = array_map(function($sUInt) {return gmp_import($sUInt);}, $aLtpaPubKey);
  DEBUG && array_walk($aRSAPubKey, function ($gInt, $iKey) {printf("getPubKey(): final aRSAPubKey[%d] == '%s'\n", $iKey, gmp_strval($gInt, -16));});
  // encode to DER ASN.1 PKCS#8 X.509 public key
  $sX509PubKeyDER = \asn1\encode([
    't' => \asn1\TYPE_SEQUENCE,
    'v' => [['t' => \asn1\TYPE_SEQUENCE,
             'v' => [['t' => \asn1\TYPE_OBJECT_IDENTIFIER, 'v' => 'rsaEncryption'],
                     ['t' => \asn1\TYPE_NULL             , 'v' => NULL           ]
                    ]
            ],
            ['t' => \asn1\TYPE_BIT_STRING,
             'v' => ['t' => \asn1\TYPE_SEQUENCE,
                     'v' => array_map(function($v) {return ['t' => \asn1\TYPE_INTEGER, 'v' => $v];}, $aRSAPubKey)
                    ]
            ]
           ]
  ]);
  DEBUG && printf("getPubKey(): sX509PubKeyDER [%u] == '%s'\n", strlen($sX509PubKeyDER), bin2hex($sX509PubKeyDER));
  // encode to PEM
  $sPubKeyPEM = "-----BEGIN PUBLIC KEY-----\n".base64_encode($sX509PubKeyDER)."\n-----END PUBLIC KEY-----\n";
  DEBUG && printf("getPubKey(): sPubKeyPEM [%u] == '%s'\n", strlen($sPubKeyPEM), $sPubKeyPEM);
  return openssl_pkey_get_public($sPubKeyPEM);
}

/** helper for debug mode */
function bin2str(string $s): string {
  // how to display binary data
  static $bIsIdeaDebugMode = false;  // true: simulate IDEA debugger view output e.g. show "\x7F\x80" as "127 -128"
                                     // false: use bin2hex() to show "\x7F\x80" as "7FFF"
  if($bIsIdeaDebugMode) {
    $l = strlen($s);
    $o = '';
    for ($i = 0; $i < $l; $i++) {
      $a = ord($s[$i]);
      $o .= sprintf(" %d", ($a < 0x80 ? $a : $a - 0xFF));
    }
    $o = substr($o, 1);
  } else {
    $o = bin2hex($s);
  }
  return $o;
}

/** swap any two values */
function swap(&$a, &$b) {$t = $a; $a = $b; $b = $t;}
