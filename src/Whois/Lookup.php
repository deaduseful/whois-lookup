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
    const HOST = 'whois.iana.org';

    /** @const int Default server port. */
    const PORT = 43;

    /** @const string End of Line. */
    const EOL = "\r\n";

    /** @const int Timeout (in seconds) for query. */
    const TIMEOUT = 1;

    /** @const int Max length of content. */
    const MAX_LENGTH = 1024 * 16;

    /** @var string Query. */
    private $query = '';

    /** @var string Server host. */
    private $host = self::HOST;

    /** @var int Server port. */
    private $port = self::PORT;

    /** @var resource A streams context. */
    private $context = null;

    /** @var int Timeout for query. */
    private $timeout = self::TIMEOUT;

    /** @var int Bitmask field which may be set to any combination of connection flags. */
    private $flags = STREAM_CLIENT_CONNECT;

    /** @var string The result of the lookup. */
    private $result = '';

    /**
     * Lookup constructor.
     *
     * @param string $query
     * @param string $host
     * @param int $port
     */
    public function __construct(string $query = '', string $host = self::HOST, int $port = self::PORT)
    {
        $this->setQuery($query)
            ->setHost($host)
            ->setPort($port)
            ->setResult($this->query());
    }

    /**
     * @param string|null $query
     * @return string
     */
    public function query($query = null)
    {
        $payload = $this->preparePayload($query);
        $remoteSocket = $this->prepareRemoteSocket();
        $client = $this->prepareStreamSocketClient($remoteSocket);
        return $this->streamGetContents($client, $payload, $remoteSocket);
    }

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @param string $host
     * @return Lookup
     */
    public function setHost($host)
    {
        $this->host = $host;
        return $this;
    }

    /**
     * @return int
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * @param int $port
     * @return Lookup
     */
    public function setPort($port)
    {
        $this->port = $port;
        return $this;
    }

    /**
     * @return resource
     */
    public function getContext()
    {
        return $this->context;
    }

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * @return int
     */
    public function getFlags()
    {
        return $this->flags;
    }

    /**
     * @return string
     */
    public function getQuery(): string
    {
        return $this->query;
    }

    /**
     * @param string $query
     * @return Lookup
     */
    public function setQuery(string $query): Lookup
    {
        $this->query = $query;
        return $this;
    }

    /**
     * @return string
     */
    public function getResult(): string
    {
        return $this->result;
    }

    /**
     * @param string $result
     * @return Lookup
     */
    public function setResult(string $result): Lookup
    {
        $this->result = $result;
        return $this;
    }

    /**
     * Get the Top Level Domain Extension from a domain.
     *
     * @param $domain
     * @return string
     */
    public function getExtension($domain)
    {
        if (filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
            return pathinfo($domain, PATHINFO_EXTENSION);
        }
        return '';
    }

    /**
     * Parse Whois Server from the lookup result.
     *
     * @param string $haystack
     * @param string $needle
     * @return string
     */
    public function parseServer($haystack, $needle = 'whois')
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

    /**
     * @return string
     */
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

    /**
     * @param $query
     * @return string
     */
    private function preparePayload($query): string
    {
        if ($query === null) {
            $query = $this->getQuery();
        }
        if (empty($query)) {
            throw new UnexpectedValueException("Query cannot be empty");
        }
        $query = trim($query);
        $payload = $query . self::EOL;
        return $payload;
    }

    /**
     * @param string $remoteSocket
     * @return bool|resource
     */
    private function prepareStreamSocketClient(string $remoteSocket)
    {
        $context = $this->getContext();
        $timeout = $this->getTimeout();
        $flags = $this->getFlags();
        if ($context === null) {
            $context = stream_context_create();
        }
        $client = @stream_socket_client($remoteSocket, $errorNumber, $errorMessage, $timeout, $flags, $context);
        if ($client === false) {
            throw new UnexpectedValueException(sprintf("Unable to open socket (%s) Error: %s (#%d)", $remoteSocket, $errorMessage, $errorNumber), $errorNumber);
        }
        return $client;
    }

    /**
     * @param bool|resource $client
     * @param string $payload
     * @param string $remoteSocket
     * @return bool|string
     */
    private function streamGetContents($client, string $payload, string $remoteSocket)
    {
        fwrite($client, $payload);
        $contents = stream_get_contents($client, self::MAX_LENGTH);
        fclose($client);
        if ($contents === false) {
            throw new UnexpectedValueException(sprintf("Failed to get a response (%s)", $remoteSocket));
        }
        return $contents;
    }
}
