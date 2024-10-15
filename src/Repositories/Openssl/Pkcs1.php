<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiEncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiReceiverInterface;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\UseMyPrivateKeyInterface;
use JuanchoSL\Cryptology\Contracts\UseMyPublicKeyInterface;
use JuanchoSL\Cryptology\Contracts\UsePasswordInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PasswordTrait;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PrivateKeyTrait;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PublicKeyTrait;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\RemoteCertificatesTrait;
use JuanchoSL\Exceptions\PreconditionRequiredException;

class Pkcs1 extends AbstractOpenssl implements MultiReceiverInterface, MultiEncryptableInterface, DecryptableInterface, UseMyPrivateKeyInterface, UseMyPublicKeyInterface, UsePasswordInterface, SignableInterface, VerifyableInterface
{

    use PrivateKeyTrait, PublicKeyTrait, PasswordTrait, RemoteCertificatesTrait, PasswordTrait;

    const OPTION_ALGO = 'algo';
    const OPTION_CIPHER = 'cipher';

    protected string $algo = 'SHA256';
    protected string $cipher = 'AES-256-CBC';

    public function encrypt(string $origin): array
    {
        if (empty($this->certificates)) {
            throw new PreconditionRequiredException("The receivers public keys are required in order to encrypt a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $receivers = [];
        foreach ($this->certificates as $certificate) {
            $receivers[] = openssl_get_publickey($certificate) or $this->error();
        }
        $sealed_data = '';
        $env_keys = [];
        openssl_seal(
            $origin,
            $sealed_data,
            $env_keys,
            $receivers,
            $this->cipher,
            $iv
        ) or $this->error();
        return [$iv . $sealed_data, $env_keys];
    }

    public function decrypt(string $origin): string
    {
        if (empty($this->private_key) || empty($this->password)) {
            throw new PreconditionRequiredException("The private key and the message password is required in order to decrypt a message");
        }

        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $open_data = '';
        $iv = openssl_cipher_iv_length($this->cipher) or $this->error();
        openssl_open(
            substr($origin, $iv),
            $open_data,
            $this->password,
            $this->private_key,
            $this->cipher,
            substr($origin, 0, $iv)
        ) or $this->error();
        return $open_data;
    }

    public function sign(string $origin): bool|string
    {
        if (empty($this->private_key)) {
            throw new PreconditionRequiredException("The private key is required in order to sign a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        $signature = '';
        if (openssl_sign($origin, $signature, $this->private_key, $this->algo)) {
            return $origin . PHP_EOL . PHP_EOL . $signature;
        }
        return false;
    }

    public function verify(string $origin): bool|string
    {
        if (empty($this->certificates)) {
            throw new PreconditionRequiredException("The public keys from accepted senders are required in order to verify a message");
        }
        if ($this->checkForFile($origin)) {
            $origin = $this->getFromFile($origin);
        }
        list($origin, $signature) = explode(PHP_EOL . PHP_EOL, $origin, 2);
        if (openssl_verify($origin, $signature, $this->certificates, $this->algo) > 0) {
            return $origin;
        }
        return false;
    }
}