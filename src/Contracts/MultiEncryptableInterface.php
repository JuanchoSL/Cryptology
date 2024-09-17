<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface MultiEncryptableInterface
{
    /**
     * Encrypt a message using the provided credential, included previously
     * @param string $text A message string in plain text or a path that contains the original message
     * @return array An array containing as first element the encrypted message, and as second element, another array with the 
     * specyfic passphrases for any receiver included
     */
    public function encrypt(string $text): array;
}