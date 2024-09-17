<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface UseMyCerficateInterface
{
    /**
     * Set the certificate for use as credential
     * @param \OpenSSLCertificate|string $key The credential, An Certificate, the value or a filepath thats include it
     * @return void
     */
    public function setCertificate(\OpenSSLCertificate|string $key): static;
}