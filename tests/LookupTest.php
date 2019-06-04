<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Deaduseful\Whois\Lookup;
use PHPUnit\Framework\TestCase;

class lookupTest extends TestCase
{
    public function testLookup()
    {
        $query = 'example.com';
        $lookup = new Lookup();
        $result = $lookup->query($query);
        $this->assertStringContainsStringIgnoringCase($query, $result);
    }
}
