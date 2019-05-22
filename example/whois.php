<?php

include __DIR__ . '/../src/Whois/Lookup.php';

$whois = new Deaduseful\Whois\Lookup();
echo $whois->lookup('uk');
