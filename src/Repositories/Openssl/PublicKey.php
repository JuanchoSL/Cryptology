<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\Contracts\UseMyPublicKeyInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PublicKeyTrait;
use JuanchoSL\Exceptions\PreconditionRequiredException;

class PublicKey extends AbstractAsymmetric implements UseMyPublicKeyInterface
{

    use PublicKeyTrait;

    public function encrypt(string $origin): string
    {
        if (empty($this->public_key)) {
            throw new PreconditionRequiredException("The public key is required in order to encrypt a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $response = '';
        $chunks = intval(openssl_pkey_get_details($this->public_key)['bits'] / 8) - 11;
        foreach (str_split($origin, $chunks) as $chunk) {
            if (openssl_public_encrypt($chunk, $result, $this->public_key, $this->padding) === false) {
                $this->error();
            }
            $response .= $result;
        }
        return $response;
    }

    public function decrypt(string $origin): string
    {
        if (empty($this->public_key)) {
            throw new PreconditionRequiredException("The public key is required in order to decrypt a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $response = '';
        $chunks = intval(openssl_pkey_get_details($this->public_key)['bits'] / 8);
        foreach (str_split($origin, $chunks) as $chunk) {
            if (openssl_public_decrypt($chunk, $result, $this->public_key, $this->padding) === false) {
                $this->error();
            }
            $response .= $result;
        }
        return $response;
    }

}