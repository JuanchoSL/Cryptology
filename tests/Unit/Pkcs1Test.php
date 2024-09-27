<?php

namespace JuanchoSL\Cryptology\Tests;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiEncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiReceiverInterface;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\UseMyPrivateKeyInterface;
use JuanchoSL\Cryptology\Contracts\UsePasswordInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Pkcs1;
use PHPUnit\Framework\TestCase;

class Pkcs1Test extends TestCase
{
    protected function providerCryptoData(): array
    {
        $cert_path = dirname(__DIR__, 2);
        $public_origin = $cert_path . DIRECTORY_SEPARATOR . getenv('SERVER_PUBLIC');
        $key_origin = $cert_path . DIRECTORY_SEPARATOR .  getenv('SERVER_PRIVATE');
        $public_receiver = $cert_path . DIRECTORY_SEPARATOR .  getenv('SOCKET_PUBLIC');
        $key_receiver = $cert_path . DIRECTORY_SEPARATOR .  getenv('SOCKET_PRIVATE');
        return [
            'PrivatePublicString' => [
                (new Pkcs1())->setRemotes([file_get_contents($public_receiver)])->setPrivateKey($key_origin),//->setPublicKey($public_origin),
                (new Pkcs1())->setRemotes([file_get_contents($public_origin)])->setPrivateKey($key_receiver),//->setPublicKey($public_receiver),
            ],
            'PrivatePublicFile' => [
                (new Pkcs1)->setRemotes(['file://' . $public_receiver])->setPrivateKey($key_origin),//->setPublicKey($public_origin),
                (new Pkcs1)->setRemotes(['file://' . $public_origin])->setPrivateKey($key_receiver),//->setPublicKey($public_receiver),
            ],
            'PrivatePublicFilepath' => [
                (new Pkcs1())->setRemotes([$public_receiver])->setPrivateKey($key_origin),//->setPublicKey($public_origin),
                (new Pkcs1())->setRemotes([$public_origin])->setPrivateKey($key_receiver),//->setPublicKey($public_receiver),
            ]
        ];
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecode(MultiEncryptableInterface&UsePasswordInterface $crypter, MultiEncryptableInterface&UsePasswordInterface&DecryptableInterface $decrypter)
    {
        $text = 'message for encode';

        $data = $crypter->encrypt($text);
        $this->assertIsArray($data);
        $decrypted = $decrypter->setPassword(current($data[1]))->decrypt($data[0]);
        $this->assertEquals($text, $decrypted);
    }
    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeFile(MultiEncryptableInterface&UsePasswordInterface $crypter, MultiEncryptableInterface&UsePasswordInterface&DecryptableInterface $decrypter)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phpunit.xml');//exit;
        
        $data = $crypter->encrypt($text);
        $this->assertIsArray($data);
        $decrypted = $decrypter->setPassword(current($data[1]))->decrypt($data[0]);
        $this->assertEquals(file_get_contents($text), $decrypted);
    }
    
    /**
     * @dataProvider providerCryptoData
     */
    public function testSignedFile(SignableInterface&MultiEncryptableInterface&UseMyPrivateKeyInterface $origin,VerifyableInterface&DecryptableInterface&UsePasswordInterface&MultiReceiverInterface $decrypter)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phpunit.xml');//exit;
        $crypted = $origin->encrypt($text);
        $sign = $origin->sign($crypted[0]);
        $public_origin = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . getenv('SERVER_PUBLIC');
        $decrypter->setRemotes([$public_origin, current($crypted[1])]);
        $decrypter->setPassword(current($crypted[1]));
        $decrypted = $decrypter->verify($sign);
        $this->assertIsString($decrypted);
        $decrypted = $decrypter->decrypt($decrypted);
        $this->assertIsString($decrypted);
        $this->assertEquals(file_get_contents($text), $decrypted);
    }
}