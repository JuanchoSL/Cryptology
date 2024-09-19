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
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('gpg');
        shell_exec("gpg -q --output {$destiny} --encrypt --armor --recipient {$this->key} {$origin}");
        $response = file_get_contents($destiny);
        @unlink($destiny);
        return $response;
    }

    public function decrypt(string $origin): string
    {
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('msg');
        shell_exec("gpg -q --output {$destiny} --decrypt {$origin}");
        $response = file_get_contents($destiny);
        @unlink($destiny);
        return $response;
    }

    public function sign(string $origin): string
    {
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('sig');
        shell_exec("gpg -u {$this->key} --output {$destiny} --clear-sign {$origin}");
        $response = file_get_contents($destiny);
        @unlink($destiny);
        return $response;
    }

    public function verify(string $origin): string|bool
    {
        if (!$this->checkForFile($origin)) {
            $origin = $this->saveFile($origin, $path);
        }
        $destiny = $this->generateFile('msg');
        $remotes = implode("' -e '", $this->remotes);
        //echo "gpg -q --output {$destiny} --decrypt {$origin} 2>&1 | grep -e {$remotes}";exit;
        $result = shell_exec("gpg -q --output {$destiny} --decrypt {$origin} 2>&1 | grep -e '{$remotes}'");
        //$result = shell_exec("gpg -q --output {$destiny} --decrypt {$origin} 2>&1 | grep 'gpg: Good signature from '");
        if (!empty($result)) {
            $response = file_get_contents($destiny);
            @unlink($destiny);
            return $response;
        }
        return false;
    }
}