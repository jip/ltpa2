<?php
/**
 * asn1.php test #2
 * ver. 1.0.1
 * (c) 2023-05-02 zhuravlov.ip@ya.ru
 */

const DEBUG = true;

require 'asn1.php';

$data = [
  't' => asn1\TYPE_SEQUENCE,
  'v' => [
    ['t' => asn1\TYPE_INTEGER, 'v' => 0],
    ['t' => asn1\TYPE_INTEGER, 'v' => 1],
    ['t' => asn1\TYPE_INTEGER, 'v' => 15],
    ['t' => asn1\TYPE_INTEGER, 'v' => 16],
    ['t' => asn1\TYPE_INTEGER, 'v' => 127],
    ['t' => asn1\TYPE_INTEGER, 'v' => 128],
    ['t' => asn1\TYPE_INTEGER, 'v' => 255],
    ['t' => asn1\TYPE_INTEGER, 'v' => 256],
    ['t' => asn1\TYPE_INTEGER, 'v' => 32767],
    ['t' => asn1\TYPE_INTEGER, 'v' => 32768],
    ['t' => asn1\TYPE_INTEGER, 'v' => 65535],
    ['t' => asn1\TYPE_INTEGER, 'v' => 65536],
    ['t' => asn1\TYPE_INTEGER, 'v' => PHP_INT_MAX],  // x86_64: 9223372036854775807 0x7FFFFFFFFFFFFFFF
    ['t' => asn1\TYPE_INTEGER, 'v' => -1],
    ['t' => asn1\TYPE_INTEGER, 'v' => -16],
    ['t' => asn1\TYPE_INTEGER, 'v' => -17],
    ['t' => asn1\TYPE_INTEGER, 'v' => -128],
    ['t' => asn1\TYPE_INTEGER, 'v' => -129],
    ['t' => asn1\TYPE_INTEGER, 'v' => -256],
    ['t' => asn1\TYPE_INTEGER, 'v' => -257],
    ['t' => asn1\TYPE_INTEGER, 'v' => -32768],
    ['t' => asn1\TYPE_INTEGER, 'v' => -32769],
    ['t' => asn1\TYPE_INTEGER, 'v' => -65536],
    ['t' => asn1\TYPE_INTEGER, 'v' => -65537],
    ['t' => asn1\TYPE_INTEGER, 'v' => PHP_INT_MIN],  // x86_64: -9223372036854775808 0x8000000000000000
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(0)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(1)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(127)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(128)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(255)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(256)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(PHP_INT_MAX)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('9223372036854775808')],  // PHP_INT_MAX+1
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('0xFFFFFFFFFFFFFFFF')],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(-1)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(-128)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(-129)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(-256)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(-257)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init(PHP_INT_MIN)],
    ['t' => asn1\TYPE_INTEGER, 'v' => gmp_init('-9223372036854775809')]  // PHP_INT_MIN-1
  ]
];

echo asn1\encode($data); // raw output
// the result can be checked using:
//   php asn1-test-2.php > asn1-test-2.out.der
//   openssl asn1parse -i -dump -inform der -in asn1-test-2.out.der > asn1-test-2.out.asn1
//   xxd -d -p asn1-test-2.out.der > asn1-test-2.out.xxd
