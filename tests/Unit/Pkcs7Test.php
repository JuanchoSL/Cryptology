<?php

namespace JuanchoSL\Cryptology\Tests;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiReceiverInterface;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Pkcs7;
use PHPUnit\Framework\TestCase;

class Pkcs7Test extends TestCase
{
    protected function providerCryptoData(): array
    {
        $cert_path = dirname(__DIR__, 2);
        $public_origin = $cert_path . DIRECTORY_SEPARATOR . getenv('SERVER_CERT');
        $key_origin = $cert_path . DIRECTORY_SEPARATOR .  getenv('SERVER_PRIVATE');
        $public_receiver = $cert_path . DIRECTORY_SEPARATOR .  getenv('SOCKET_CERT');
        $key_receiver = $cert_path . DIRECTORY_SEPARATOR .  getenv('SOCKET_PRIVATE');
        return [
            'FewPublicString' => [
                (new Pkcs7())->setRemotes([file_get_contents($public_receiver)])->setPrivateKey(file_get_contents($key_origin))->setCertificate(file_get_contents($public_origin)),
                (new Pkcs7())->setRemotes([file_get_contents($public_origin)])->setPrivateKey(file_get_contents($key_receiver))->setCertificate(file_get_contents($public_receiver)),
            ],
            'Fewpublic_receiverFile' => [
                (new Pkcs7())->setRemotes(['file://' . $public_receiver])->setPrivatekey('file://' . $key_origin)->setCertificate('file://' . $public_origin),
                (new Pkcs7())->setRemotes(['file://' . $public_origin])->setPrivateKey('file://' . $key_receiver)->setCertificate('file://' . $public_receiver),
            ],
            'Fewpublic_receiverFilepath' => [
                (new Pkcs7())->setRemotes([$public_receiver])->setPrivateKey($key_origin)->setCertificate($public_origin),
                (new Pkcs7())->setRemotes([$public_origin])->setPrivateKey($key_receiver)->setCertificate($public_receiver),
            ]
        ];
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecode(EncryptableInterface $crypter,DecryptableInterface $decrypter)
    {
        $text = 'message for encode';

        $data = $crypter->encrypt($text);
        $decrypted = $decrypter->decrypt($data);
        $this->assertEquals($text, $decrypted);
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeFile(EncryptableInterface $origin,DecryptableInterface $decrypter)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phpunit.xml');//exit;
        $crypted = $origin->encrypt($text);
        $decrypted = $decrypter->decrypt($crypted);
        $this->assertEquals(file_get_contents($text), $decrypted);
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testSignedFile(SignableInterface&EncryptableInterface $origin,VerifyableInterface&DecryptableInterface $decrypter)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phpunit.xml');//exit;
        $crypted = $origin->sign($text);
        $crypted = $origin->encrypt($crypted);
        $crypted = $origin->sign($crypted);
        $decrypted = $decrypter->verify($crypted);
        $this->assertIsString($decrypted);
        $decrypted = $decrypter->decrypt($decrypted);
        $decrypted = $decrypter->verify($decrypted);
        $this->assertEquals(file_get_contents($text), $decrypted);
    }
}