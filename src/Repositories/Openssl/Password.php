<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\UsePasswordInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PasswordTrait;

class Password extends AbstractOpenssl implements EncryptableInterface, DecryptableInterface, UsePasswordInterface
{

    use PasswordTrait;

    const OPTION_CIPHER = 'cipher';

    protected string $cipher = 'AES-256-CBC';

    public function encrypt(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $ivLength = openssl_cipher_iv_length($this->cipher) or $this->error();
        $iv = openssl_random_pseudo_bytes($ivLength) or $this->error();
        $crypted = openssl_encrypt($origin, $this->cipher, md5($this->password), OPENSSL_RAW_DATA, $iv) or $this->error();
        return $ivLength . strrev($iv) . $crypted;
    }

    public function decrypt(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $ivLength = openssl_cipher_iv_length($this->cipher) or $this->error();
        $offset = strlen((string) $ivLength);
        $iv = strrev(substr($origin, $offset, $ivLength));
        $offset += strlen($iv);
        $result = openssl_decrypt(substr($origin, $offset), $this->cipher, md5($this->password), OPENSSL_RAW_DATA, $iv) or $this->error();
        return $result;
    }

}