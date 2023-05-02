<?php
/**
 * asn1.php test #1
 * ver. 1.0.0
 * (c) 2023-05-02 zhuravlov.ip@ya.ru
 */

const DEBUG = true;

require 'asn1.php';

// generate RSAPrivateKey ASN1 structure according to [1] and RFC 2313 [2] in der format
// references:
// [1] ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.asn
// [2] https://www.ietf.org/rfc/rfc2313.txt

$key_data = [
  't' => asn1\TYPE_SEQUENCE,
  'v' => [
    ['t' => asn1\TYPE_INTEGER, 'v' => 0                                                                                                                                                                                                                                                                             ],  // version
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0xE0C349E62A8DB30AEEF295A5E2A586E72CC09DEEDD275B62737910C0D7F7C56C769D8C92D8C4FCE148427F6EF131C1A034ED378BD1871C5B3D6276A708BCAB41E90D9D61C5406A714F2F6422822304552E1C752D5A5E9BBBF9FD1429386F50B44B076B824EF0213E5E8956B14CCDCE139BAD425C8F0466C7CFFCAE57CA1C0D17')],  // modulus
    ['t' => asn1\TYPE_INTEGER, 'v' => 0x10001                                                                                                                                                                                                                                                                       ],  // publicExponent
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0xA44CBD617E2BD4FCA20D3C6D65CF805CCEEF02C4106FEBB27D1CBBAD6C7217A420D52C645007379FEAF58937ED22651B1A75698C509F06907FBFD1626AD5980D985E84494CE9F11E5CBDE96B3AE4A34B8730EBD3A4173129C2B1603B3A0595A1502688222ED7811E570395E27492173F8F76C9D0C55A054F0A7BF0D61CC6D6A9')],  // privateExponent
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0xF68239CEF65143C60A85F0CA6F844EB9F65F3D7393716DA8E11D0C5B637B5710721C85ABAE607FAFEE1892303C7EDA67310C4D42ABF5352E0589E64BB549C1C3')                                                                                                                                ],  // prime1
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0xE96AB83114F8FBB6FF93C7F32A8E16EB57FDC0D778ECF2E77A38679FB16F3EC439D4DD40AADD88141B018B6D92A610CB0991CA61759B110A94C40A89D4BEDE1D')                                                                                                                                ],  // prime2
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0x6AA845E2EA6896EE653736CC201C1B0413397A193BBE643821CEB3BE06F922DE96C1088513D9E4E5761B638543678F8FFE84D818F4D60FC06DDD10ABC930B489')                                                                                                                                ],  // exponent1
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0x3852BE1B69DA22B327BCBB34DC01E959E4A3A092DDE51F3FE7E8106922619B9DB1EEC16CC74E2975E08660E491CC6CA4F1AC324F8E175AE758BA6D6890E375A9')                                                                                                                                ],  // exponent2
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0xD5319B47F24A316B76E6E2EB2E19195AEF68D378E6D0E366C55D149BD89A10011F3FEDB9A8EAAC488FEC1C589AC3DDF79214D9C15113C4DC8BB180DE9AF51E9F')                                                                                                                                ]   // coefficient
  ]
];

echo asn1\encode($key_data);
// the result can be checked using:
//   php asn1-test-1.php > asn1-test-1.out.der
//   openssl asn1parse -i -dump -inform der -in asn1-test-1.out.der > asn1-test-1.out.asn1
//   xxd -d -p asn1-test-1.out.der > asn1-test-1.out.xxd
//   openssl rsa -in asn1-test-1.out.der -inform der -text -noout > asn1-test-1.out.dump
