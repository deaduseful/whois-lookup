<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$query = isset($argv[1]) ? $argv[1] : 'com';
$lookup = new Deaduseful\Whois\Lookup($query);
$result = $lookup->query();
echo $lookup->parseServer($result) . PHP_EOL;
