<?php
/**
 * Abstract Syntax Notation One (ASN.1) [1] encoder/decoder based on [2]
 * ver. 2.1.0
 * (c) 2017-02-13 zhuravlov.ip@ya.ru
 *
 * @note
 * - DER encoding rules
 * - only a tiny subset required by LTPA2 is implemented
 *
 * @see
 * [1] http://www.itu.int/ITU-T/recommendations/search.aspx?type=30&status=F&main=1&title=ASN.1&pg_size=20
 * [2] https://github.com/vakata/asn1
 */

// prevent arguments type casting, force arguments and return values type checking
declare(strict_types = 1);

namespace asn1;

/** @var int constructive form bit */
const FORM_CONSTRUCTIVE      = 0x20;

/** @var int data type IDs suported */
const TYPE_INTEGER           = 0x02;
const TYPE_BIT_STRING        = 0x03;
const TYPE_OCTET_STRING      = 0x04;
const TYPE_NULL              = 0x05;
const TYPE_OBJECT_IDENTIFIER = 0x06;
const TYPE_SEQUENCE          = 0x10;

/** @var array OIDs suported */
const oids = [
  'rsaEncryption' => '1.2.840.113549.1.1.1'
];

/**
 * encode data to ASN.1 binary string
 *
 * @param  array  $tree each element is a map ['t'=>typeID, 'v'=>value] where:
 *                      - typeID is one of TYPE_* const
 *                      - value is one of:
 *                        - an array of elements in $tree format (so, recursive tree structure),
 *                          those elements will be finally joined according to keys order
 *                        - value itself of some PHP type agreed with typeID
 * @return string       ASN.1 binary string representing $tree
 */
function encode(array $tree): string {
  if(is_array($tree) && count($tree) == 2 && array_key_exists('t', $tree) && array_key_exists('v', $tree)) {
    switch($tree['t']) {  // check ID
      case TYPE_INTEGER:
        $body = encode_int_body($tree['v']);
        break;
      case TYPE_OBJECT_IDENTIFIER:
        $body = encode_obj_body($tree['v']);
        break;
      case TYPE_NULL:
        $body = '';
        break;
      case TYPE_BIT_STRING:
        if(is_array($tree['v'])) {
          $tree['v'] = "\x0".encode($tree['v']);  // hack: length always divisible by 8
        }
        // default to octet string if no mapping is present
      case TYPE_OCTET_STRING:
        $body = $tree['v']; // base64_decode($tree['v']);
        break;
      case TYPE_SEQUENCE:
        $tree['t'] |= FORM_CONSTRUCTIVE;  // set the constructive bit
        $body = encode_seq_body($tree['v']);
        break;
      default:
        exit("type ID '{$tree['t']}' not supported\n");
    }
  } else {
    exit("asn1\encode() argument not recognized\n");
  }
  // ASN.1 is a triplet: TAG LEN BODY
  return chr($tree['t']) . encode_len(strlen($body)) . $body;
}

/**
 * encode integer block's body
 */
function encode_int_body($val): string {
  if(is_string($val)) {
    $body = $val;
  } else {
    if(is_object($val) && 'GMP' == get_class($val)) {
      $sign = gmp_sign($val);
      if($sign == -1) {
        $val = gmp_com2($val);  // rewrite by two's complement form
      }
      // export and workaround "bug" #74017: gmp_export(0) == ''
      $body = ($sign == 0) ? "\x0" : gmp_export($val, 1, GMP_BIG_ENDIAN);  // MSB goes before LSB in address space
    } elseif(is_int($val)) {
      $sign = int_sign($val);
      $body = encode_uint($val);
    } else {
      exit("asn1\encode_int_body() argument datatype is invalid\n");
    }
    // adjust sign bit
    $msb = ord($body);
    if($msb > 0x7F && $sign == 1) {
      $body = "\x00$body";
    } elseif($msb < 0x80 && $sign == -1) {
      $body = "\xFF$body";
    }
  }
  return $body;
}

/**
 * encode object block's body
 */
function encode_obj_body(string $val): string {
  if(array_key_exists($val, oids)) {
    $oid = oids[$val];
    $parts = explode('.', $oid);
    $body = chr(40 * $parts[0] + $parts[1]);
    for ($i = 2; $i < count($parts); $i++) {
      $temp = '';
      if (!$parts[$i]) {
        $temp = "\0";
      } else {
        while ($parts[$i]) {
          $temp = chr(0x80 | $parts[$i] & 0x7F) . $temp;
          $parts[$i] >>= 7;
        }
        $temp[strlen($temp) - 1] = $temp[strlen($temp) - 1] & chr(0x7F);
      }
      $body .= $temp;
    }
  } else {
    exit("asn1\encode_obj_body() object name not recognized\n");
  }
  return $body;
}

/**
 * encode sequence block's body
 */
function encode_seq_body(array $seq): string {
  array_walk($seq, function (&$val, $key) {$val = encode($val);});
  ksort($seq);
  return implode($seq);
}

/**
 * encode block's length
 */
function encode_len(int $len): string {
  if ($len > 0x7F) {
    $sLength = encode_uint($len);
    return chr(0x80 | strlen($sLength)) . $sLength;
  } else {
    return chr($len);
  }
}

/**
 * encode unsigned integer
 *
 * @param  int    $uint value to encode
 * @return string       big-edian representation
 */
function encode_uint(int $i): string {
  static $fmt = [2=>'n', 4=>'N', 8=>'J'][PHP_INT_SIZE];  // machine dependent BE uint format
  if($i == 0) {
    $s = "\x0";
  } elseif($i == -1) {
    $s = "\xFF";
  } else {
    $s = ltrim(pack($fmt, $i), $i > 0 ? "\x0" : "\xFF");
  }
  return $s;
}

/**
 * Derive two's complement form. GMP numbers are represented internally as a pair
 * of sign flag and an absolute value. Therefore negative values must be converted
 * to two's complement form before export to ASN.1.
 *
 * @param  object GMP $g integer to complement
 * @return object GMP    integer in two's complement form
 *
 * @note gmp_export losts sign (!!!)
 * @note atrernative (gmp_com2 := 1 + gmp_com) lacks padding sign bits
 *
 * @example
 *   PHP 32-bit int n    gmp_init(n)   gmp_com2(n)   gmp_init(n)+gmp_com2(n)
 *    32767  0x00007FFF  ( 1, 0x7FFF)  ( 1, 0x8001)  ( 1, 0x10000)
 *   -32767  0xFFFF8001  (-1, 0x7FFF)  (-1, 0x8001)  (-1, 0x10000)
 *   -32768  0xFFFF8000  (-1, 0x8000)  (-1, 0x8000)  (-1, 0x10000)
 *    32768  0x00008000  ( 1, 0x8000)  ( 1, 0x8000)  ( 1, 0x10000)
 */
function gmp_com2(\GMP $g): \GMP {
  $abs = gmp_init('0x1'.str_repeat('00', strlen(gmp_export($g)))) - gmp_abs($g);
  return $g < 0 ? -$abs : $abs;
}

/** sign() for integers */
function int_sign(int $i): int {
  return ($i > 0) ? 1 : (($i < 0) ? -1 : 0);
}
