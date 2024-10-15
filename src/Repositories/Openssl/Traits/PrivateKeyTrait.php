<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

trait PrivateKeyTrait
{
    protected \OpenSSLAsymmetricKey|\OpenSSLCertificate|string $private_key;

    public function setPrivateKey(\OpenSSLAsymmetricKey|\OpenSSLCertificate|string $credential, string|null $passphrase = null): static
    {
        if ($this->checkForFile($credential)) {
            $credential = $this->getFromFile($credential);
        }
        $this->private_key = openssl_get_privatekey($credential, $passphrase) or $this->error();
        return $this;
    }

}