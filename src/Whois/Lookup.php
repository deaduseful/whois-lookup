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
        if ($query === null) {
            $query = $this->getQuery();
        }
        $payload = trim($query) . self::EOL;
        $host = $this->getHost();
        if (empty($host)) {
            throw new UnexpectedValueException("Host cannot be empty");
        }
        $port = $this->getPort();
        $remoteSocket = sprintf('tcp://%s:%d', $host, $port);
        $context = $this->getContext();
        $timeout = $this->getTimeout();
        $flags = $this->getFlags();
        if ($context === null) {
            $context = stream_context_create();
        }
        $client = @stream_socket_client($remoteSocket, $errorNumber, $errorMessage, $timeout, $flags, $context);
        if ($client === false) {
            throw new UnexpectedValueException(sprintf("Unable to open socket (%s:%d) Error: %s (#%d)", $host, $port, $errorMessage, $errorNumber), $errorNumber);
        }
        fwrite($client, $payload);
        $output = stream_get_contents($client, self::MAX_LENGTH);
        fclose($client);
        if ($output === false) {
            throw new UnexpectedValueException(sprintf("Failed to get a response (%s:%d)", $host, $port));
        }
        return $output;
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
}
