<?php

namespace JuanchoSL\Cryptology\Tests;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Password;
use JuanchoSL\Cryptology\Repositories\Openssl\PrivateKey;
use JuanchoSL\Cryptology\Repositories\Openssl\PublicKey;
use PHPUnit\Framework\TestCase;

class OpenSSLTest extends TestCase
{

    protected function providerCryptoData(): array
    {
        $cert_path = dirname(__DIR__, 2);
        $public = $cert_path . DIRECTORY_SEPARATOR  . getenv('SERVER_PUBLIC');
        $key = $cert_path . DIRECTORY_SEPARATOR .  getenv('SERVER_PRIVATE');
        return [
            'PrivatePublicString' => [
                (new PrivateKey())->setPrivateKey(credential: file_get_contents($key)),
                (new PublicKey())->setPublicKey(file_get_contents($public)),
            ],
            'PrivatePublicFile' => [
                (new PrivateKey())->setPrivateKey('file://' . $key),
                (new PublicKey())->setPublicKey('file://' . $public),
            ],
            'PrivatePublicFilepath' => [
                (new PrivateKey())->setPrivateKey($key),
                (new PublicKey())->setPublicKey($public),
            ],
            'PublicPrivateString' => [
                (new PublicKey())->setPublicKey(file_get_contents($public)),
                (new PrivateKey())->setPrivateKey(file_get_contents($key)),
            ],
            'PublicPrivateFile' => [
                (new PublicKey())->setPublicKey('file://' . $public),
                (new PrivateKey())->setPrivateKey('file://' . $key),
            ],
            'PublicPrivateFilepath' => [
                (new PublicKey())->setPublicKey($public),
                (new PrivateKey())->setPrivateKey($key),
            ],
            'Password' => [
                (new Password())->setPassword('password'),
                (new Password())->setPassword('password')
            ]
        ];
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeText(EncryptableInterface $origin, DecryptableInterface $destiny)
    {
        $text = 'message for encode';
        $crypted = $origin->encrypt($text);
        $decrypted = $destiny->decrypt($crypted);
        $this->assertEquals($text, $decrypted);
    }
    
    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeFile(EncryptableInterface $origin, DecryptableInterface $destiny)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . '.gitignore');//exit;
        $crypted = $origin->encrypt($text);
        $decrypted = $destiny->decrypt($crypted);
        $this->assertEquals(file_get_contents($text), $decrypted);
    }
}