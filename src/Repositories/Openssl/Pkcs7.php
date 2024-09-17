<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiReceiverInterface;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\UseMyCerficateInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\CertificateTrait;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\PrivateKeyTrait;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\RemoteCertificatesTrait;
use JuanchoSL\Exceptions\PreconditionRequiredException;

class Pkcs7 extends AbstractOpenssl implements EncryptableInterface, DecryptableInterface, SignableInterface, VerifyableInterface, UseMyCerficateInterface, MultiReceiverInterface
{

    use PrivateKeyTrait, CertificateTrait, RemoteCertificatesTrait;

    const OPTION_CYPHER = 'cipher';

    protected int $cipher = OPENSSL_CIPHER_AES_256_CBC;

    public function encrypt(string $origin): string
    {
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('txt');
        openssl_pkcs7_encrypt($origin, $destiny, $this->certificates, [], 0, $this->cipher);
        $result = file_get_contents($destiny);
        @unlink($destiny);
        return $result;
    }

    public function decrypt(string $origin): string
    {
        if (empty($this->private_key) || empty($this->certificate)) {
            throw new PreconditionRequiredException("The private key and your certificate are requireds in order to decrypt a message");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('txt');
        openssl_pkcs7_decrypt($origin, $destiny, $this->certificate, $this->private_key) or $this->error();
        $result = file_get_contents($destiny);
        @unlink($destiny);
        return $result;
    }

    public function sign(string $origin): bool|string
    {
        if (empty($this->private_key) || empty($this->certificate)) {
            throw new PreconditionRequiredException("The private key and your certificate are requireds in order to apply a signature");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('txt');
        openssl_pkcs7_sign($origin, $destiny, $this->certificate, $this->private_key, [], PKCS7_DETACHED) or $this->error();

        $result = file_get_contents($destiny);
        @unlink($destiny);
        return $result;
    }

    public function verify(string $origin): bool|string
    {
        if (empty($this->certificates)) {
            throw new PreconditionRequiredException("The certificate is required in order to verify a signature");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $cert_path = $this->saveFile(implode(PHP_EOL, $this->certificates), filename: $cert_path);
        $message = $this->generateFile('msg');
        if (openssl_pkcs7_verify($origin, PKCS7_NOVERIFY, $cert_path, [], $cert_path, $message) > 0) {
            $result = file_get_contents($message);
            @unlink($message);
            @unlink($path);
            @unlink($cert_path);
            return $result;
        } else {
            return false;
        }
    }
}