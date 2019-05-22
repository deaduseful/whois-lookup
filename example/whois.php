<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$lookup = new Deaduseful\Whois\Lookup();
echo $lookup->lookup('example.com', 'whois.verisign-grs.com');
