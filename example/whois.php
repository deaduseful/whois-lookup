<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$lookup = new Deaduseful\Whois\Lookup();
$query = isset($argv[1]) ? $argv[1] : 'example.com';
$host = 'whois.verisign-grs.com';
echo $lookup->lookup($query, $host);
