<?php

namespace Deaduseful\Whois;

use RuntimeException;
use UnexpectedValueException;

/**
 * Class Lookup
 * @package Deaduseful\Whois
 */
class Lookup
{
    /** @const string Default server host. */
    protected const HOST = 'whois.iana.org';

    /** @const int Default server port. */
    protected const PORT = 43;

    /** @const string End of Line. */
    protected const EOL = "\r\n";

    /** @const int Timeout (in seconds) for query. */
    protected const TIMEOUT = 1;

    /** @const int Max length of content. */
    protected const MAX_LENGTH = 1024 * 16;

    protected ?string $query = '';

    /** @var string Server host. */
    protected string $host = self::HOST;

    /** @var int Server port. */
    protected int $port = self::PORT;

    /** @var resource A stream's context. */
    protected $context = null;

    /** @var int Timeout for query. */
    protected int $timeout = self::TIMEOUT;

    /** @var int Bitmask field which may be set to any combination of connection flags. */
    protected int $flags = STREAM_CLIENT_CONNECT;

    /** @var ?string The result of the lookup. */
    protected ?string $result = null;

    protected ?string $proxyHost = null;
    protected ?int $proxyPort = null;
    protected ?string $proxyUser = null;
    protected ?string $proxyPass = null;

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
        if ($this->proxyHost && $this->proxyPort) {
            return $this->performWithProxy();
        } else {
            $payload = $this->preparePayload();
            $remoteSocket = $this->prepareRemoteSocket();
            return $this->getContents($payload, $remoteSocket);
        }
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
            throw new UnexpectedValueException('Host cannot be empty');
        }
        $port = $this->getPort();
        if (empty($port)) {
            throw new UnexpectedValueException('Port cannot be empty');
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
            throw new RuntimeException(sprintf('Failed to get a response (%s)', $remoteSocket));
        }
        return $contents;
    }

    private function prepareStreamSocketClient(string $remoteSocket)
    {
        $context = $this->getContext();
        $timeout = $this->getTimeout();
        $flags = $this->getFlags();
        return $this->getClient($remoteSocket, $timeout, $flags, $context);
    }

    public function getContext()
    {
        return $this->context ?: stream_context_create();
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
    public function parseServer(string $haystack, string $needle = 'whois', $default = null): ?string
    {
        $lines = explode(PHP_EOL, $haystack);
        foreach ($lines as $line) {
            if (strpos($line, ':')) {
                list($key, $value) = explode(':', $line, 2);
                if (trim($key) === $needle) {
                    $result = trim($value);
                    if ($result) {
                        return strtolower($result);
                    }
                }
            }
        }
        return $default;
    }

    private function getClient(string $remoteSocket, int $timeout, int $flags, $context)
    {
        $client = @stream_socket_client($remoteSocket, $errorNumber, $errorMessage, $timeout, $flags, $context);
        if ($client === false) {
            throw new RuntimeException($errorMessage, $errorNumber);
        }
        return $client;
    }

    public function setFlags(int $flags): Lookup
    {
        $this->flags = $flags;
        return $this;
    }

    public function setProxy(string $host, int $port, ?string $user = null, ?string $pass = null): Lookup
    {
        $this->proxyHost = $host;
        $this->proxyPort = $port;
        $this->proxyUser = $user;
        $this->proxyPass = $pass;
        return $this;
    }

    private function performWithProxy(): string
    {
        $query = $this->preparePayload();
        $proxySocket = 'tcp://' . $this->proxyHost . ':' . $this->proxyPort;
        $proxyContext = stream_context_create([
            'socket' => [
                'bindto' => '0:0',
            ],
        ]);

        $proxyConnection = stream_socket_client($proxySocket, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $proxyContext);

        if (!$proxyConnection) {
            throw new RuntimeException("Failed to connect to the SOCKS5 proxy server: $errstr ($errno)");
        }

        $handshake = "\x05\x01";
        if ($this->proxyUser && $this->proxyPass) {
            $handshake .= "\x02";
        } else {
            $handshake .= "\x00";
        }
        fwrite($proxyConnection, $handshake);

        $response = fread($proxyConnection, 2);
        if (empty($response)) {
            throw new RuntimeException("Failed to get response");
        }
        if ($response[0] == "\x05" && $response[1] == "\x02") {
            $auth = "\x01" . chr(strlen($this->proxyUser)) . $this->proxyUser . chr(strlen($this->proxyPass)) . $this->proxyPass;
            fwrite($proxyConnection, $auth);
            $response = fread($proxyConnection, 2);
            if ($response[0] != "\x01" || $response[1] != "\x00") {
                throw new RuntimeException("Failed to authenticate with SOCKS5 proxy server");
            }
        }

        $request = "\x05\x01\x00\x03" . chr(strlen($this->host)) . $this->host . pack('n', $this->port);
        fwrite($proxyConnection, $request);
        $response = fread($proxyConnection, 1024);

        if (empty($response)) {
            throw new RuntimeException("Failed to get response");
        }

        if ($response[0] != "\x05" || $response[1] != "\x00") {
            throw new RuntimeException("Failed to establish connection to the destination server");
        }

        @fwrite($proxyConnection, $query);
        $response = stream_get_contents($proxyConnection);
        fclose($proxyConnection);

        if ($response === false) {
            throw new RuntimeException("Failed to get response from the destination server");
        }

        return $response;
    }
}
