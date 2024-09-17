<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface UsePasswordInterface
{
    /**
     * Set the password for a message in order to encrypt or decrypt it.
     * @param string $password The password of or for a message
     * @return void
     */
    public function setPassword(string $password): static;
}