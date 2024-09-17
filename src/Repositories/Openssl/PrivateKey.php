<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\UseMyPrivateKeyInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PrivateKeyTrait;
use JuanchoSL\Exceptions\PreconditionRequiredException;

class PrivateKey extends AbstractAsymmetric implements EncryptableInterface, DecryptableInterface, UseMyPrivateKeyInterface
{

    use PrivateKeyTrait;

    public function encrypt(string $origin): string
    {
        if (empty($this->private_key)) {
            throw new PreconditionRequiredException("The private key is required in order to encrypt a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $response = '';
        foreach (str_split($origin, $this->chunk) as $chunk) {
            if (openssl_private_encrypt($chunk, $result, $this->private_key, $this->padding) === false) {
                $this->error();
            }
            $response .= $result;
        }
        return $response;
    }
    
    public function decrypt(string $origin): string
    {
        if (empty($this->private_key)) {
            throw new PreconditionRequiredException("The private key is required in order to decrypt a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $response = '';
        foreach (str_split($origin, $this->chunk) as $chunk) {
            if (openssl_private_decrypt($chunk, $result, $this->private_key, $this->padding) === false) {
                $this->error();
            }
            $response .= $result;
        }
        return $response;
    }
}