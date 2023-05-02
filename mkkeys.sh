#!/bin/bash

# Generate keys for WebSphere LTPA2 cookie codec
# ver. 1.0.0
# (c) 2023-04-26 zhuravlov.ip@ya.ru

# config
ASCII='\000\003\005\006\011\012\014\017\021\022\024\027\030\033\035\036\041\042\044\047\050\053\055\056\060\063\065\066\071\072\074\077\101\102\104\107\110\113\115\116\120\123\125\126\131\132\134\137\140\143\145\146\151\152\154\157\161\162\164\167\170\173\175\176\201\202\204\207\210\213\215\216\220\223\225\226\231\232\234\237\240\243\245\246\251\252\254\257\261\262\264\267\270\273\275\276\300\303\305\306\311\312\314\317\321\322\324\327\330\333\335\336\341\342\344\347\350\353\355\356\360\363\365\366\371\372\374\377'
ASCII_WITH_PARITY='\001\002\004\007\010\013\015\016\020\023\025\026\031\032\034\037\040\043\045\046\051\052\054\057\061\062\064\067\070\073\075\076\100\103\105\106\111\112\114\117\121\122\124\127\130\133\135\136\141\142\144\147\150\153\155\156\160\163\165\166\171\172\174\177\200\203\205\206\211\212\214\217\221\222\224\227\230\233\235\236\241\242\244\247\250\253\255\256\260\263\265\266\271\272\274\277\301\302\304\307\310\313\315\316\320\323\325\326\331\332\334\337\340\343\345\346\351\352\354\357\361\362\364\367\370\373\375\376'
AWK_RSA_KEY_GEOM='
  BEGIN {FS="[ =:]+"}
  NR == 4 && $3 == "d" && $4 == "1" && $5 == "hl" && $7="l" && $9 == "prim" && $10="INTEGER" {print 1,$2+$6,$8}  # e
  NR == 5 && $3 == "d" && $4 == "1" && $5 == "hl" && $7="l" && $9 == "prim" && $10="INTEGER" {print 0,$2+$6,$8}  # d
  NR == 6 && $3 == "d" && $4 == "1" && $5 == "hl" && $7="l" && $9 == "prim" && $10="INTEGER" {print 2,$2+$6,$8}  # p
  NR == 7 && $3 == "d" && $4 == "1" && $5 == "hl" && $7="l" && $9 == "prim" && $10="INTEGER" {print 3,$2+$6,$8}  # q'
AWK_RSA_PKEY_GEOM1='
  BEGIN {FS="[ =:]+"}
  $0 ~ /BIT STRING/ {print $2,$6}'
AWK_RSA_PKEY_GEOM2='
  BEGIN {FS="[ =:]+"}
  NR == 1 && $3 == "d" && $4 == "0" && $5 == "hl" && $7="l" && $9 == "cons" && $10="SEQUENCE" {print    $6,-1}  # header
  NR == 2 && $3 == "d" && $4 == "1" && $5 == "hl" && $7="l" && $9 == "prim" && $10="INTEGER"  {print $2+$6,$8}  # n
  NR == 3 && $3 == "d" && $4 == "1" && $5 == "hl" && $7="l" && $9 == "prim" && $10="INTEGER"  {print $2+$6,$8}  # e'
# /config

function Explain_And_Exit () {
  local SCRIPT_NAME=$(basename $0)
  echo "Generate key file for WebSphere LTPA2 cookie codec

Usage:
    $SCRIPT_NAME -h | [passphrase_file [3des_key_file [rsa_private_key_file]]]

Parameters:
    -h
        Show help and exit
    passphrase_file
        File with passphrase, not newline-terminated
    3des_key_file
        random 24 bytes, binary data
    rsa_private_key_file
        RSA private key in PEM format

Examples:
    $SCRIPT_NAME -h
    $SCRIPT_NAME
    $SCRIPT_NAME passwd.txt
    $SCRIPT_NAME passwd.txt 3DES_key.bin
    $SCRIPT_NAME passwd.txt 3DES_key.bin RSA_pvt_key.pem"
  exit 1
}

# output $1, exit
function Exit () { echo "Failed: $1" >&2; exit 2; }

# usage: ... | Debug proceeding.log | ...
function Debug () {
  cat       # debug is disabled
  # tee $1  # debug is enabled: put stdin to both stdout and $1 (which is supposed to be a file name)
}

# check environment
shopt -s lastpipe || Exit "Bash version 4.2+ is required"  # to read by read builtin from pipe

# check input parameters
[ $# -gt 3 -o $# -eq 1 -a "$1" == "-h" ] && Explain_And_Exit
(($# > 0)) && { [ -s "$1" ] || Exit "$1 file not found or is empty"; }
(($# > 1)) && { [ -s "$2" ] || Exit "$2 file not found or is empty"; }
(($# > 2)) && { [ -s "$3" ] || Exit "$3 file not found or is empty"; }

# prepare password
{ [ $# -gt 0 ] && cat "$1" || cat                                                   | Debug 01_passwd.txt; }                  |  # enter password, then press Ctrl+D twice to terminate, don't press Enter
openssl dgst -sha1 -binary                                                          | Debug 02_passwd.sha1.bin                |  # sha1(password)
{ cat; echo -ne "\x0\x0\x0\x0"; }                                                   | Debug 03_passwd.sha1.bin.pad            |  # pad(sha1(password))
tr $ASCII $ASCII_WITH_PARITY                                                        | Debug 04_passwd.sha1.bin.pad.adj        |  # adjust parity
xxd -p > 05_passwd.sha1.bin.pad.adj.hex

# prepare 3DES key
{ [ $# -gt 1 ] && cat "$2" || openssl rand 24 | Debug 06_3DES_key.bin; }                                                      |  # get or generate 3DES key
openssl des -e -des-ede3 -nosalt -K $(cat 05_passwd.sha1.bin.pad.adj.hex)           | Debug 07_3DES_key.enc                   |  # encrypt BY 3DES-EDE3
base64 -w 0 > 08_3DES_key.enc.b64                                                                                                # encode by base64 without line wrapping

# get keys in DER format
[ $# -gt 2 ] || openssl genrsa -out 09_RSA_key.pem -rand /dev/random 2048                                                        # generate RSA keypair in PEM format if not supplied
openssl rsa -in ${3:-09_RSA_key.pem} -out 10_RSA_key.der  -outform der         2> /dev/null                                      # convert from PEM to DER format
openssl rsa -in ${3:-09_RSA_key.pem} -out 11_RSA_pkey.der -outform der -pubout 2> /dev/null                                      # extract public key

# prepare private key material
openssl asn1parse -i -dump -inform der -in 10_RSA_key.der                           | Debug 12_RSA_key.asn1                   |  # parse RSA private key
awk "$AWK_RSA_KEY_GEOM"                                                                                                       |  # output triplet (order,offset,length) for d,e,p,q parts only
sort -k 1,1                                                                                                                   |  # reorder (e,d,p,q) to (d,e,p,q)
{ tee 13_RSA_key.geom; (($(wc -l < 13_RSA_key.geom) == 4)) || Exit "private key not recognized in ${3:-09_RSA_key.pem}"; }    |  # check parse result
while read order offset len; do
  (($order == 0)) && printf "%08x" $len | xxd -p -r
  dd skip=$offset count=$len if=10_RSA_key.der bs=1 2> /dev/null
done                                                                                | Debug 14_WS_key.raw                     |  # compose key material (len(d),d,e,p,q)
openssl des -e -des-ede3 -nosalt -K $(cat 05_passwd.sha1.bin.pad.adj.hex)           | Debug 15_WS_key.raw.enc                 |  # encrypt by 3DES-EDE3
base64 -w 0 > 16_WS_key.raw.enc.b64                                                                                              # encode by base64 without line wrapping

# prepare public key material
openssl asn1parse -i -dump -inform der -in 11_RSA_pkey.der                          | Debug 17_RSA_pkey.asn1                  |  # parse RSA public key
awk "$AWK_RSA_PKEY_GEOM1"                                                                                                     |  # output (offset,length) for BIT STRING
{ tee 18_RSA_pkey.geom1; (($(wc -l < 18_RSA_pkey.geom1) == 1)) || Exit "public key not recognized in ${3:-09_RSA_key.pem}"; } |  # check parse result
read global_offset global_hl                                                                                                     # extract offset,length (lastpipe option in action)
openssl asn1parse -i -dump -inform der -in 11_RSA_pkey.der -strparse $global_offset | Debug 19_RSA_pkey.asn1                  |  # parse BIT STRING where n,e are packed in
awk "$AWK_RSA_PKEY_GEOM2"                                                                                                     |  # find (offset,length) for header,n,e parts
{ tee 20_RSA_pkey.geom2; (($(wc -l < 20_RSA_pkey.geom2) == 3)) || Exit "public key not recognized in ${3:-09_RSA_key.pem}"; } |  # check parse result
while read offset len; do
  (($len == -1)) && global_offset=$(($global_offset + $global_hl + 1)) || dd skip=$(($global_offset + $offset)) count=$len if=11_RSA_pkey.der bs=1 2> /dev/null
done                                                                                | Debug 21_WS_pkey.raw                    |  # compose key material (n,e)
base64 -w 0 > 22_WS_pkey.raw.b64                                                                                                 # encode by base64 without line wrapping

# compose key file content
cat << END1
com.ibm.websphere.ltpa.3DESKey=$(sed 's/=/\\=/' 08_3DES_key.enc.b64)
com.ibm.websphere.ltpa.PrivateKey=$(sed 's/=/\\=/' 16_WS_key.raw.enc.b64)
com.ibm.websphere.ltpa.PublicKey=$(sed 's/=/\\=/' 22_WS_pkey.raw.b64)
END1
