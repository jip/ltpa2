<?php
/**
 * ltpa2.php test #1
 * ver. 2.0.1
 * (c) 2023-05-02 zhuravlov.ip@ya.ru
 *
 * @usage:
 *   php ltpa2-test-1.php
 */

require 'ltpa2.php';

static $aResult         = [true => 'passed', false => 'failed'];
static $sConfigFilename = 'keys.properties';
static $sPassword       = 'abc.123';

$aConfig = ltpa2\readConfig($sConfigFilename);

$sLtpa2Plaintext  = 'expire:1410205320000$u:user\:defaultWIMFileBasedRealm/uid=wpsadmin,o=defaultWIMFileBasedRealm%1410205320000';
$sLtpa2Ciphertext = 'B3d3F5J9A7vJEgCF74C9jpiMF0n4gDbKWjWVWrX01+kprmCCbbz4dLJwc/uaDUmiOkOclzt+gc9Wuz+dgDRAd9Hacpy6KPvjp0+zF/5jXlLBDOJSecgl3DDwK6oEkXCq4lQGiAh+fpZoenjv6Ex0ALs6nuVnE8GGlqM+ljJiNCEBGSvT1oIn7W2YlKcDq+Mon1W+qJSaQjBYLd7CmT4t4Pg8sVO8vnJEedUXbUkQRRyOmXPuaCm85ig6BzFyqmLZG2JYsQrNL4afJBp4TSKLe7+VreaLqiXyZiqj4cOcNTgCQnW8M+X3tC7z0pJXtP86oK8L572bzFA9E7FZxJJJ1s+OdpvxlMDdpld9xrRxKjNVtIhCu5bj1IqslQzEiNky';

printf("original plaintext: '%s'\n", $sLtpa2Plaintext);
$sLtpa2CiphertextTest = ltpa2\encrypt($sLtpa2Plaintext, $sPassword, $aConfig['com.ibm.websphere.ltpa.3DESKey'], $aConfig['com.ibm.websphere.ltpa.PrivateKey']);
printf("encryption test %s\n", $aResult[$sLtpa2CiphertextTest === $sLtpa2Ciphertext]);

printf("original ciphertext: '%s'\n", $sLtpa2Ciphertext);
$sLtpa2PlaintextTest = ltpa2\decrypt($sLtpa2Ciphertext, $sPassword, $aConfig['com.ibm.websphere.ltpa.3DESKey'], $aConfig['com.ibm.websphere.ltpa.PublicKey']);
printf("decryption test %s\n", $aResult[$sLtpa2PlaintextTest === $sLtpa2Plaintext]);
