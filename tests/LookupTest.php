<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Deaduseful\Whois\Lookup;
use PHPUnit\Framework\TestCase;

class lookupTest extends TestCase
{
    /**
     * @dataProvider domainTests
     * @param string $query
     * @param string $host
     */
    public function testLookup($query, $host)
    {
        $lookup = new Lookup();
        $result = $lookup->setHost($host)->query($query);
        $this->assertStringContainsStringIgnoringCase($query, $result);
    }

    /**
     * @return array
     */
    public function domainTests() {
        return [
            ['example.com', 'whois.verisign-grs.com'],
            ['uk', 'whois.iana.org'],
            ['example.co.uk', 'whois.nic.uk'],
        ];
    }
}
