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
class GpgConsole extends AbstractCrypted implements EncryptableInterface, DecryptableInterface, SignableInterface, VerifyableInterface, MultiReceiverInterface, UseMyPrivateKeyInterface
{

    protected string $key;
    protected string $password;
    protected array $remotes;

    public function setPrivateKey(string|\OpenSSLAsymmetricKey|\OpenSSLCertificate $key, string|null $password = null): static
    {
        $this->key = $key;
        $this->password = $password;
        return $this;
    }

    public function setRemotes(array $remotes): static
    {
        $this->remotes = $remotes;
        return $this;
    }

    public function encrypt(string $origin): string
    {
        if (empty($this->remotes)) {
            throw new PreconditionRequiredException("The remote USER_ID is required in order to encrypt a message");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $recipients = implode(" --recipient ", $this->remotes);
        if (false) {
            $response = shell_exec("gpg -q --textmode --encrypt --armor --recipient {$recipients} {$origin}");
        } else {
            $destiny = $this->generateFile('gpg');
            shell_exec("gpg -q --output {$destiny} --encrypt --armor --recipient {$recipients} {$origin}");
            $response = file_get_contents($destiny);
            @unlink($destiny);
        }
        return $response;
    }

    public function decrypt(string $origin): string
    {
        if (empty($this->key) || empty($this->password)) {
            throw new PreconditionRequiredException("The private key and password are requireds in order to decrypt a message");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        if (true) {
            $response = shell_exec("gpg -q --yes --pinentry-mode loopback -u {$this->key} --passphrase \"{$this->password}\" --textmode --decrypt {$origin}");
        } else {
            $destiny = $this->generateFile('msg');
            shell_exec("gpg -q --yes --pinentry-mode loopback -u {$this->key} --passphrase \"{$this->password}\" --output {$destiny} --decrypt {$origin}");
            $response = file_get_contents($destiny);
            @unlink($destiny);
        }

        return $response;
    }

    public function sign(string $origin): string
    {
        if (empty($this->key) || empty($this->password)) {
            throw new PreconditionRequiredException("The private key and password are requireds in order to sign a message");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        if (false) {
            echo "gpg -q -u {$this->key} --passphrase {$this->password} --textmode --clear-sign {$origin}";exit;
            $response = shell_exec("gpg -q -u {$this->key} --passphrase {$this->password} --textmode --clear-sign {$origin}");
        } else {
            $destiny = $this->generateFile('sig');
            shell_exec("gpg -u {$this->key} --passphrase {$this->password} --output {$destiny} --clear-sign {$origin}");
            $response = file_get_contents($destiny);
            @unlink($destiny);
        }

        return $response;
    }

    public function verify(string $origin): string|bool
    {
        if (empty($this->key) || empty($this->password)) {
            throw new PreconditionRequiredException("The private key and password are requireds in order to verify a message");
        }
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('msg');
        $remotes = implode("' -e '", $this->remotes);
        $result = shell_exec("gpg -q -u {$this->key} --passphrase \"{$this->password}\" --output {$destiny} --decrypt {$origin} 2>&1 | grep -e '{$remotes}'");
        if (!empty($result)) {
            $response = file_get_contents($destiny);
            @unlink($destiny);
            return $response;
        }
        return false;
    }
}