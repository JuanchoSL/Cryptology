<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface MultiReceiverInterface
{
    /**
     * An array of certificates for the remote entities
     * @param array $remote_certificates An array of credentials, certificates, public keys, or file path that contains the credentials
     * @return void
     */
    public function setRemotes(array $remote_certificates): static;
}