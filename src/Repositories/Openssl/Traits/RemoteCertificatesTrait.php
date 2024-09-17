<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

trait RemoteCertificatesTrait
{

    protected array $certificates;

    public function setRemotes(array $remote_certificates): static
    {
        $this->certificates = [];
        foreach ($remote_certificates as $credential) {
            if (is_string($credential) && is_file($credential)) {
                $credential = file_get_contents($credential);
            }
            $this->certificates[] = $credential;
        }
        return $this;
    }

}