<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$lookup = new Deaduseful\Whois\Lookup();
$query = $argv[1] ?? 'example.com';
$host = $argv[2] ?? 'whois.verisign-grs.com';
$port = $argv[3] ?? 43;
echo $lookup->setQuery($query)->setHost($host)->getResult();
