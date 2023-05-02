<?php
/**
 * asn1.php test #3
 * ver. 1.0.1
 * (c) 2023-05-02 zhuravlov.ip@ya.ru
 */

const DEBUG = true;

require 'asn1.php';

// generate RSAPrivateKey ASN1 structure according to [1] and RFC 2313 [2] in der format
// references:
// [1] ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.asn
// [2] https://www.ietf.org/rfc/rfc2313.txt

$key_data = [
  't' => \asn1\TYPE_SEQUENCE,
  'v' => [['t' => \asn1\TYPE_SEQUENCE,
           'v' => [['t' => \asn1\TYPE_OBJECT_IDENTIFIER, 'v' => 'rsaEncryption'],
                   ['t' => \asn1\TYPE_NULL             , 'v' => NULL           ]
                  ]
          ],
          ['t' => \asn1\TYPE_BIT_STRING,
           'v' => ['t' => \asn1\TYPE_SEQUENCE,
                   'v' => array_map(function($v) {return ['t' => \asn1\TYPE_INTEGER, 'v' => $v];}, [0x11223344, 0xAABBCCDD])
                  ]
          ]
         ]
];

echo asn1\encode($key_data);
// the result can be checked using:
//   php asn1-test-3.php > asn1-test-3.out.der
//   openssl asn1parse -i -dump -inform der -in asn1-test-3.out.der > asn1-test-3.out.asn1
//   xxd -d -p asn1-test-3.out.der > asn1-test-3.out.xxd
//   openssl rsa -in asn1-test-3.out.der -inform der -pubin -text -noout > asn1-test-3.out.dump
