<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

trait PublicKeyTrait
{
    protected \OpenSSLAsymmetricKey|\OpenSSLCertificate|string $public_key;

    public function setPublicKey(\OpenSSLAsymmetricKey|\OpenSSLCertificate|string $credential): static
    {
        if ($this->checkForFile($credential)) {
            $credential = $this->getFromFile($credential);
        }
        $this->public_key = openssl_pkey_get_public($credential);
        return $this;
    }

}