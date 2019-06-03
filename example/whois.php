<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$lookup = new Deaduseful\Whois\Lookup();
$query = isset($argv[1]) ? $argv[1] : 'example.com';
$host = isset($argv[2]) ? $argv[2] : 'whois.verisign-grs.com';
$port = isset($argv[3]) ? $argv[3] : 43;
echo $lookup->lookup($query, $host, $port);
