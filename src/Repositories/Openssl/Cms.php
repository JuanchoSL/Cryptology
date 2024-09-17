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

class Cms extends AbstractOpenssl implements EncryptableInterface, DecryptableInterface, SignableInterface, VerifyableInterface, UseMyCerficateInterface, MultiReceiverInterface
{

    use PrivateKeyTrait, CertificateTrait, RemoteCertificatesTrait;

    const OPTION_ENCODING = 'encoding';
    const OPTION_CIPHER = 'cipher';

    protected int $encoding = OPENSSL_ENCODING_DER;
    protected int $cipher = OPENSSL_CIPHER_AES_256_CBC;

    public function encrypt(string $origin): string
    {
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('txt');
        openssl_cms_encrypt($origin, $destiny, $this->certificates, [], OPENSSL_CMS_BINARY | OPENSSL_CMS_NOSIGS | OPENSSL_CMS_NOVERIFY, $this->encoding, $this->cipher);
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
        $crt = $this->certificate;
        if (!$this->checkForFile($crt)) {
            $crt = $this->saveFile($this->certificate, $crt_path);
        }

        openssl_cms_decrypt($origin, $destiny, 'file://' . $crt, $this->private_key, $this->encoding) or $this->error();
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
        touch($destiny);
        $crt = $this->certificate;
        if ($this->encoding == OPENSSL_ENCODING_DER || !$this->checkForFile($crt)) {
            $crt = 'file://' . $this->saveFile($this->certificate, $crt_path);
        }
        openssl_cms_sign($origin, $destiny, $crt, $this->private_key, [], OPENSSL_CMS_BINARY, $this->encoding) or $this->error();

        $result = file_get_contents($destiny);
        @unlink($destiny);
        return $result;
    }

    public function verify(string $origin): bool|string
    {
        if (empty($this->certificates)) {
            throw new PreconditionRequiredException("The signer certificate is required in order to verify a signature");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $cert_path = $this->saveFile(implode(PHP_EOL, $this->certificates), filename: $cert_path);
        $message = $this->generateFile('msg');
        if (openssl_cms_verify($origin, OPENSSL_CMS_NOVERIFY | OPENSSL_CMS_BINARY, $cert_path, [], $cert_path, $message, null, null, $this->encoding) > 0) {
            $result = file_get_contents($message);
            @unlink($message);
            @unlink($path);
            @unlink($cert_path);
            return $result;
        } else {
            $this->error();
            return false;
        }
    }
}