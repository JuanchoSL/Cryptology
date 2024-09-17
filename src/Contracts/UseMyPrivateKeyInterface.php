<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface UseMyPrivateKeyInterface
{
    /**
     * Set the certificate as PEM format, the private key as value or a filepath to the file
     * @param \OpenSSLAsymmetricKey|\OpenSSLCertificate|string $key the element to use as credential
     * @param string $password The password of a private key if exists
     * @return void
     */
    public function setPrivateKey(\OpenSSLAsymmetricKey|\OpenSSLCertificate|string $key, string $password = null): static;
}