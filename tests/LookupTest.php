<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Deaduseful\Whois\Lookup;
use PHPUnit\Framework\TestCase;

class LookupTest extends TestCase
{
    /**
     * @dataProvider domainTests
     */
    public function testLookup(string $query, string $host)
    {
        $lookup = new Lookup();
        $result = $lookup->setHost($host)->query($query);
        $this->assertStringContainsStringIgnoringCase($query, $result);
    }

    public function domainTests(): array
    {
        return [
            ['example.com', 'whois.verisign-grs.com'],
            ['uk', 'whois.iana.org'],
            ['example.co.uk', 'whois.nic.uk'],
        ];
    }
}
