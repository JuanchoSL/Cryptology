<?php

namespace JuanchoSL\Cryptology\Tests;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiEncryptableInterface;
use JuanchoSL\Cryptology\Contracts\MultiReceiverInterface;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Cryptology\Repositories\Gpg\Gnupg;
use JuanchoSL\Cryptology\Repositories\Gpg\GpgConsole;
use JuanchoSL\Cryptology\Repositories\Openssl\Pkcs1;
use JuanchoSL\Cryptology\Repositories\Openssl\Cms;
use JuanchoSL\Cryptology\Repositories\Openssl\Pkcs7;
use PHPUnit\Framework\TestCase;

class SignaturesTest extends TestCase
{
    protected function providerCryptoData(): array
    {
        $cert_path = dirname(__DIR__, 2);
        $public_origin = $cert_path . DIRECTORY_SEPARATOR . getenv('SERVER_CERT');
        $key_origin = $cert_path . DIRECTORY_SEPARATOR . getenv('SERVER_PRIVATE');
        $public_receiver = $cert_path . DIRECTORY_SEPARATOR . getenv('SOCKET_CERT');
        $key_receiver = $cert_path . DIRECTORY_SEPARATOR . getenv('SOCKET_PRIVATE');
        return [
            'Gnupg' => [
                (new Gnupg())->setRemotes([getenv('GPG_CLIENT_KEY')]),
                (new Gnupg())->setRemotes([getenv('GPG_SERVER_KEY')])->setPrivateKey(getenv('GPG_CLIENT_KEY'), getenv('GPG_CLIENT_PASS')),//->setPublicKey($public_receiver),
            ],
            'GpgConsole' => [
                (new GpgConsole())->setRemotes([getenv('GPG_CLIENT_KEY')])->setPrivateKey(getenv('GPG_SERVER_KEY'), getenv('GPG_SERVER_PASS')),
                (new Gnupg())->setRemotes([getenv('GPG_SERVER_KEY')])->setPrivateKey(getenv('GPG_CLIENT_KEY'), getenv('GPG_CLIENT_PASS')),//->setPublicKey($public_receiver),
            ],
            /*
            'PrivatePublicString' => [
                (new Pkcs1())->setRemotes([file_get_contents($public_receiver)])->setPrivateKey($key_origin),//->setPublicKey($public_origin),
                (new Pkcs1())->setRemotes([file_get_contents($public_origin)])->setPrivateKey($key_receiver),//->setPublicKey($public_receiver),
            ],
            */
            'FewPublicString' => [
                (new Pkcs7())->setRemotes([file_get_contents($public_receiver)])->setPrivateKey(file_get_contents($key_origin))->setCertificate(file_get_contents($public_origin)),
                (new Pkcs7())->setRemotes([file_get_contents($public_origin)])->setPrivateKey(file_get_contents($key_receiver))->setCertificate(file_get_contents($public_receiver)),
            ],
            'PemFewpublic_receiverFilepath' => [
                (new Cms([Cms::OPTION_ENCODING => OPENSSL_ENCODING_PEM]))->setRemotes([$public_receiver])->setPrivateKey($key_origin)->setCertificate($public_origin),
                (new Cms([Cms::OPTION_ENCODING => OPENSSL_ENCODING_PEM]))->setRemotes([$public_origin])->setPrivateKey($key_receiver)->setCertificate($public_receiver),
            ],
            'DerFewPublicString' => [
                (new Cms([Cms::OPTION_ENCODING => OPENSSL_ENCODING_DER]))->setRemotes([file_get_contents($public_receiver)])->setPrivateKey(file_get_contents($key_origin))->setCertificate(file_get_contents($public_origin)),
                (new Cms([Cms::OPTION_ENCODING => OPENSSL_ENCODING_DER]))->setRemotes([file_get_contents($public_origin)])->setPrivateKey(file_get_contents($key_receiver))->setCertificate(file_get_contents($public_receiver)),
            ]
        ];
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testSignedFile(SignableInterface|EncryptableInterface|MultiEncryptableInterface $origin, VerifyableInterface|MultiReceiverInterface|DecryptableInterface $decrypter)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phpunit.xml');//exit;
        $crypted = $origin->encrypt($text);
        $crypted = $origin->sign($crypted);
        if (is_array($crypted)) {
            $password = $crypted[1];
            $crypted = $crypted[0];
        }
        $decrypted = $decrypter->verify($crypted);
        $this->assertIsString($decrypted);
    }
}