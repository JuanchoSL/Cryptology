<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\Contracts\UseMyPrivateKeyInterface;
use JuanchoSL\Exceptions\PreconditionRequiredException;

class PrivateKey extends AbstractAsymmetric implements UseMyPrivateKeyInterface
{

    public function encrypt(string $origin): string
    {
        if (empty($this->private_key)) {
            throw new PreconditionRequiredException("The private key is required in order to encrypt a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $chunks = intval(openssl_pkey_get_details($this->private_key)['bits'] / 8) - 11;
        $response = '';
        foreach (str_split($origin, $chunks) as $chunk) {
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
        $chunks = intval(openssl_pkey_get_details($this->private_key)['bits'] / 8);
        foreach (str_split($origin, $chunks) as $chunk) {
            if (openssl_private_decrypt($chunk, $result, $this->private_key, $this->padding) === false) {
                $this->error();
            }
            $response .= $result;
        }
        return $response;
    }

}