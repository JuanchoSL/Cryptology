<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface DecryptableInterface
{
    /**
     * Decrypt a message using the required credential, included previously
     * @param string $text A message string encrypted or a path that contains the encrypted message
     * @return string The result of decryption
     */
    public function decrypt(string $text): string;
}