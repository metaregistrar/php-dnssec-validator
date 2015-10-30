<?php
include_once('validate.php');


if ($argc<1) {
    die("Usage: test.php <domainname>\n\n");
}
$domainname = $argv[1];

try {
    validateDomain($domainname);
} catch (DnsException $e) {
    echo "ERROR: ".$e->getMessage()."\n";
}