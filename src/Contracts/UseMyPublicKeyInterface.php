<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface UseMyPublicKeyInterface
{
    /**
     * Set the certificate as PEM format, the public key as value or a filepath to the file
     * @param \OpenSSLAsymmetricKey|\OpenSSLCertificate|string $key the element to use as credential
     * @return void
     */
    public function setPublicKey(\OpenSSLAsymmetricKey|\OpenSSLCertificate|string $key): static;
}