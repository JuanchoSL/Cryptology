<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface SignableInterface
{
    /**
     * Generate a signature from the provided text, usually the message to send
     * @param string $text The text to sign
     * @return string|bool The signature or false if has any error 
     */
    public function sign(string $text): string|bool;
}