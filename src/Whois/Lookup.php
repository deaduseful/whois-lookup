<?php

namespace Deaduseful\Whois;

use UnexpectedValueException;

class Lookup {
    /** @var string Default whois server host. */
    const HOST = 'whois.iana.org';

    /** @var int Default whois server port. */
    const PORT = 43;

    /**
     * @param string $payload
     * @param string $host
     * @param int $port
     * @return string
     */
    private function query(string $payload, string $host = self::HOST, int $port = self::PORT)
    {
        $remoteSocket = sprintf('tcp://%s:%d', $host, $port);
        $client = stream_socket_client($remoteSocket, $errorNumber, $errorMessage);
        if ($client === false) {
            throw new UnexpectedValueException("Unable to connect: $errorMessage", $errorNumber);
        }
        fwrite($client, $payload);
        $out = stream_get_contents($client);
        fclose($client);
        return $out;
    }

    /**
     * @param $query
     * @return string
     */
    public function lookup($query) {
        return $this->query($query . PHP_EOL);
    }
}
