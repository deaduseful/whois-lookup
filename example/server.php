<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$query = $argv[1] ?? 'com';
$lookup = new Deaduseful\Whois\Lookup($query);
$result = $lookup->query($query);
echo $lookup->parseServer($result) . PHP_EOL;
