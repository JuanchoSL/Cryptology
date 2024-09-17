<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

trait CertificateTrait
{

    protected \OpenSSLCertificate|string $certificate;

    public function setCertificate(\OpenSSLCertificate|string $credential): static
    {
        if ($this->checkForFile($credential)) {
            $credential = $this->getFromFile($credential);
        }
        $this->certificate = $credential;
        return $this;
    }

}