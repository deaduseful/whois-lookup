<?php

namespace Deaduseful\Whois;

use UnexpectedValueException;

class Lookup {

    /** @var string Default whois server host. */
    const HOST = 'whois.iana.org';

    /** @var int Default whois server port. */
    const PORT = 43;

    /** @var string End of Line. */
    const EOL = "\r\n";

    /** @var int Timeout for query. */
    const TIMEOUT = 1;

    /** @var int Max length of content. */
    const MAX_LENGTH = 2048;

    /** @var array The options array for stream_context_create */
    private $options = [];

    /**
     * @param string $payload
     * @param string $host
     * @param int $port
     * @param int $timeout
     * @param int $flags
     * @param null $context
     * @return string
     */
    private function query(string $payload, string $host = self::HOST, int $port = self::PORT, int $timeout = self::TIMEOUT, $flags = STREAM_CLIENT_CONNECT, $context = null)
    {
        if (empty($host)) {
            throw new UnexpectedValueException("Host cannot be empty");
        }
        $remoteSocket = sprintf('tcp://%s:%d', $host, $port);
        if ($context === null) {
            $context = stream_context_create($this->getOptions());
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
     * @param $query
     * @param string $host
     * @param int $port
     * @return string
     */
    public function lookup($query, string $host = self::HOST, int $port = self::PORT) {
        return $this->query($query . self::EOL, $host, $port);
    }

    /**
     * @return array
     */
    private function getOptions()
    {
        return $this->options;
    }

    /**
     * @param array $options
     * @return Lookup
     */
    public function setOptions(array $options): Lookup
    {
        $this->options = $options;
        return $this;
    }
}
