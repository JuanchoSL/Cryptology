<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories;

use JuanchoSL\Cryptology\AbstractCrypted;
use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\UsePasswordInterface;
use JuanchoSL\Exceptions\PreconditionRequiredException;

class Mcrypt extends AbstractCrypted implements EncryptableInterface, DecryptableInterface, UsePasswordInterface
{

    protected string $sSecretKey;

    public function __construct(string $password)
    {
        if (!extension_loaded('mcrypt')) {
            throw new PreconditionRequiredException("The extension MCRYPT is not available");
        }
        $this->setPassword($password);
    }

    public function setPassword(string $password): static
    {
        $this->sSecretKey = $password;
        return $this;
    }

    public function encrypt(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        return @mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($this->sSecretKey), $origin, MCRYPT_MODE_ECB, @mcrypt_create_iv(@mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND));
    }

    public function decrypt(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        return str_replace("\0", '', @mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($this->sSecretKey), $origin, MCRYPT_MODE_ECB, @mcrypt_create_iv(@mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
    }
}