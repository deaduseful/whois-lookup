<?php

namespace Deaduseful\Whois;

use UnexpectedValueException;

/**
 * Class Lookup
 * @package Deaduseful\Whois
 */
class Lookup
{
    /** @const string Default server host. */
    public const HOST = 'whois.iana.org';

    /** @const int Default server port. */
    public const PORT = 43;

    /** @const string End of Line. */
    public const EOL = "\r\n";

    /** @const int Timeout (in seconds) for query. */
    public const TIMEOUT = 1;

    /** @const int Max length of content. */
    const MAX_LENGTH = 1024 * 16;

    private ?string $query = '';

    /** @var string Server host. */
    private string $host = self::HOST;

    /** @var int Server port. */
    private int $port = self::PORT;

    /** @var resource A stream's context. */
    private $context = null;

    /** @var int Timeout for query. */
    private int $timeout = self::TIMEOUT;

    /** @var int Bitmask field which may be set to any combination of connection flags. */
    private int $flags = STREAM_CLIENT_CONNECT;

    /** @var ?string The result of the lookup. */
    private ?string $result = null;

    /**
     * Lookup constructor.
     */
    public function __construct(?string $query = null, string $host = self::HOST, int $port = self::PORT)
    {
        $this->setQuery($query)
            ->setHost($host)
            ->setPort($port);
    }

    public function query(?string $query = null): string
    {
        return $this->setQuery($query)->getResult();
    }

    public function getResult(): string
    {
        if (empty($this->result)) {
            $this->setResult($this->perform());
        }
        return $this->result;
    }

    public function setResult(string $result): Lookup
    {
        $this->result = $result;
        return $this;
    }

    private function perform(): string
    {
        $payload = $this->preparePayload();
        $remoteSocket = $this->prepareRemoteSocket();
        return $this->getContents($payload, $remoteSocket);
    }

    private function preparePayload(): string
    {
        $query = $this->getQuery();
        if (empty($query)) {
            throw new UnexpectedValueException('Query cannot be empty');
        }
        $query = trim($query);
        return $query . self::EOL;
    }

    public function getQuery(): ?string
    {
        return $this->query;
    }

    public function setQuery(?string $query = null): Lookup
    {
        $this->query = $query;
        return $this;
    }

    private function prepareRemoteSocket(): string
    {
        $host = $this->getHost();
        if (empty($host)) {
            throw new UnexpectedValueException("Host cannot be empty");
        }
        $port = $this->getPort();
        if (empty($port)) {
            throw new UnexpectedValueException("Port cannot be empty");
        }
        return sprintf('tcp://%s:%d', $host, $port);
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function setHost(string $host): Lookup
    {
        $this->host = $host;
        return $this;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function setPort(int $port): Lookup
    {
        $this->port = $port;
        return $this;
    }

    private function getContents(string $payload, string $remoteSocket): string
    {
        $client = $this->prepareStreamSocketClient($remoteSocket);
        fwrite($client, $payload);
        $contents = stream_get_contents($client, self::MAX_LENGTH);
        fclose($client);
        if ($contents === false) {
            throw new UnexpectedValueException(sprintf('Failed to get a response (%s)', $remoteSocket));
        }
        return $contents;
    }

    private function prepareStreamSocketClient(string $remoteSocket)
    {
        $context = $this->getContext();
        $timeout = $this->getTimeout();
        $flags = $this->getFlags();
        if ($context === null) {
            $context = stream_context_create();
        }
        $client = stream_socket_client($remoteSocket, $errorNumber, $errorMessage, $timeout, $flags, $context);
        if ($client === false) {
            throw new UnexpectedValueException(sprintf('Unable to open socket (%s) Error: %s (#%d)', $remoteSocket, $errorMessage, $errorNumber), $errorNumber);
        }
        return $client;
    }

    public function getContext()
    {
        return $this->context;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeout(int $timeout): Lookup
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function getFlags(): int
    {
        return $this->flags;
    }

    /**
     * Parse Whois Server from the lookup result.
     */
    public function parseServer(string $haystack, string $needle = 'whois'): string
    {
        $lines = explode(PHP_EOL, $haystack);
        foreach ($lines as $line) {
            if (strpos($line, ':')) {
                list($key, $value) = explode(':', $line, 2);
                if ($key === $needle) {
                    return trim($value);
                }
            }
        }
        return '';
    }
}
