<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Gpg;

use JuanchoSL\Cryptology\AbstractCrypted;
use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiReceiverInterface;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\UseMyPrivateKeyInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Exceptions\PreconditionRequiredException;

/**
 * 
 * https://keepcoding.io/blog/como-cifrar-archivos-con-gpg/
 */
class Gnupg extends AbstractCrypted implements EncryptableInterface, DecryptableInterface, SignableInterface, VerifyableInterface, MultiReceiverInterface, UseMyPrivateKeyInterface
{

    protected $resource;
    protected string $key;

    public function __construct()
    {
        if (!extension_loaded('gnupg')) {
            throw new PreconditionRequiredException("The extension GNUPG is not available");
        }
        $this->resource = gnupg_init();
    }
    
    public function setPrivateKey(string|\OpenSSLAsymmetricKey|\OpenSSLCertificate $key, string|null $password = null): static
    {
        gnupg_adddecryptkey($this->resource, $key, $password);
        return $this;
    }

    public function setRemotes(array $remotes): static
    {
        foreach ($remotes as $remote) {
            gnupg_addencryptkey($this->resource, $remote);
        }
        return $this;
    }

    public function encrypt(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        return gnupg_encrypt($this->resource, $origin);
    }

    public function decrypt(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        return gnupg_decrypt($this->resource, $origin);
    }
    
    public function sign(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        return gnupg_sign($this->resource, $origin);
    }
    
    public function verify(string $origin): string|bool
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        if (gnupg_verify($this->resource, $origin, false, $text) !== false) {
            return $text;
        }
        return false;
    }
}