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

    /**
     * @dataProvider domainTests
     */
    public function testLookupWithProxy(string $query, string $host)
    {
        require_once __DIR__ . '/../vendor/autoload.php';
        $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
        $dotenv->load();

        $lookup = new Lookup();
        $result = $lookup
            ->setProxy(
                getenv('PROXY_HOST'),
                getenv('PROXY_PORT'),
                getenv('PROXY_USER'),
                getenv('PROXY_PASS')
            )
            ->setHost($host)
            ->query($query);
        $this->assertStringContainsStringIgnoringCase($query, $result);
    }

    public function testParseServer()
    {
        $query = 'publicdomainregistry.com';
        $expected = 'whois.publicdomainregistry.com';
        $needle = 'Registrar WHOIS Server';
        $haystack = file_get_contents(__DIR__ . '/data/' . $query . '.txt');
        $lookup = new Lookup();
        $server = $lookup->parseServer($haystack, $needle);
        $this->assertEquals($expected, $server);
    }
}
