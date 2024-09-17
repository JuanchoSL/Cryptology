<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;
use JuanchoSL\Exceptions\PreconditionRequiredException;


trait SimpleSslVerify
{

    public function verify(string $origin): bool|string
    {
        if (empty($this->certificates)) {
            throw new PreconditionRequiredException("The public keys fron accepted senders are required in order to verify a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        list($origin, $signature) = explode(PHP_EOL . PHP_EOL, $origin, 2);
        if (openssl_verify($origin, $signature, $this->certificates, "sha256WithRSAEncryption") > 0) {
            return $origin;
        }
        return false;
    }
}