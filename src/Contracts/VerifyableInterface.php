<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Contracts;

interface VerifyableInterface extends MultiReceiverInterface
{
    /**
     * Verify if a message is successly signed
     * @param string $text The message to verify
     * @return bool|string The message without the signature or false
     */
    public function verify(string $text): bool|string;
}