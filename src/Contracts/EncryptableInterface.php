<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface EncryptableInterface
{
    /**
     * Encrypt a message using the provided credential, included previously
     * @param string $text A message string in plain text or a path that contains the original message
     * @return string The result of encryption
     */
    public function encrypt(string $text): string;
}