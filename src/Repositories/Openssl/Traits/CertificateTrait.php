<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

use JuanchoSL\Exceptions\PreconditionFailedException;

trait CertificateTrait
{

    protected \OpenSSLCertificate|string $certificate;

    public function setCertificate(\OpenSSLCertificate|string $credential): static
    {
        if ($this->checkForFile($credential)) {
            $credential = $this->getFromFile($credential);
        }
        $certparsed = openssl_x509_parse($credential);
        if ($certparsed['validFrom_time_t'] > time() or $certparsed['validTo_time_t'] < time()) {
            throw new PreconditionFailedException("This certificate is not valid");
        }
        $this->certificate = $credential;
        return $this;
    }

}