<?php

namespace JuanchoSL\Cryptology\Tests;

use JuanchoSL\Cryptology\Contracts\DecryptableInterface;
use JuanchoSL\Cryptology\Contracts\EncryptableInterface;
use JuanchoSL\Cryptology\Contracts\UsePasswordInterface;
use JuanchoSL\Cryptology\Repositories\Mcrypt;
use PHPUnit\Framework\TestCase;

class McryptTest extends TestCase
{

    protected function providerCryptoData(): array
    {
        return [
            'Mcrypt' => [
                new Mcrypt('password'),
                new Mcrypt('password')
            ]
        ];
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeText(EncryptableInterface|UsePasswordInterface $origin, DecryptableInterface|UsePasswordInterface $destiny)
    {
        $text = 'message for encode';
        $crypted = $origin->encrypt($text);
        $decrypted = $destiny->decrypt($crypted);
        $this->assertEquals($text, $decrypted);
    }
    
    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeFile(EncryptableInterface|UsePasswordInterface $origin, DecryptableInterface|UsePasswordInterface $destiny)
    {
        $text = realpath(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'phpunit.xml');//exit;
        $crypted = $origin->encrypt($text);
        $decrypted = $destiny->decrypt($crypted);
        $this->assertEquals(file_get_contents($text), $decrypted);
    }
}