<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

use JuanchoSL\Exceptions\PreconditionRequiredException;

trait SimpleSslSign
{

    use PrivateKeyTrait;

    public function sign(string $origin): bool|string
    {
        if (empty($this->private_key)) {
            throw new PreconditionRequiredException("The private key is required in order to sign a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $signature = '';
        if (openssl_sign($origin, $signature, $this->private_key, OPENSSL_ALGO_SHA256)) {
            return $origin . PHP_EOL . PHP_EOL . $signature;
        }
        return false;
    }
}