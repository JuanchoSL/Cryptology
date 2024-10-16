<?php

namespace JuanchoSL\Cryptology\Tests;

use JuanchoSL\Cryptology\Repositories\Gpg\Gnupg;
use JuanchoSL\Cryptology\Repositories\Gpg\GpgConsole;
use PHPUnit\Framework\TestCase;

class GpgTest extends TestCase
{

    protected function providerCryptoData(): array
    {
        return [
            'Gnu' => [
                (new Gnupg())->setPrivateKey(getenv('GPG_SERVER_KEY'), getenv('GPG_SERVER_PASS'))->setRemotes([getenv('GPG_CLIENT_KEY')]),
                (new Gnupg())->setPrivateKey(getenv('GPG_CLIENT_KEY'), getenv('GPG_CLIENT_PASS'))->setRemotes([getenv('GPG_SERVER_KEY')]),
            ],
            'GpgConsole' => [
                (new GpgConsole())->setPrivateKey(getenv('GPG_SERVER_KEY'), getenv('GPG_SERVER_PASS'))->setRemotes([getenv('GPG_CLIENT_KEY')]),
                (new GpgConsole())->setPrivateKey(getenv('GPG_CLIENT_KEY'), getenv('GPG_CLIENT_PASS'))->setRemotes([getenv('GPG_SERVER_KEY')]),
            ],
            'GnuGpg' => [
                (new Gnupg())->setPrivateKey(getenv('GPG_SERVER_KEY'), getenv('GPG_SERVER_PASS'))->setRemotes([getenv('GPG_CLIENT_KEY')]),
                (new GpgConsole())->setPrivateKey(getenv('GPG_CLIENT_KEY'), getenv('GPG_CLIENT_PASS'))->setRemotes([getenv('GPG_SERVER_KEY')]),
            ],
            'GpgGnu' => [
                (new GpgConsole())->setPrivateKey(getenv('GPG_SERVER_KEY'), getenv('GPG_SERVER_PASS'))->setRemotes([getenv('GPG_CLIENT_KEY')]),
                (new Gnupg())->setPrivateKey(getenv('GPG_CLIENT_KEY'), getenv('GPG_CLIENT_PASS'))->setRemotes([getenv('GPG_SERVER_KEY')]),
            ],
        ];
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeText($crypter, $decrypter)
    {
        $text = 'message for encode';
        $c = $crypter->encrypt($text);
        $decrypted = $decrypter->decrypt($c);

        $this->assertEquals($text, $decrypted);
    }


    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeTextFile($crypter, $decrypter)
    {
        $origin = 'docker-compose.yml';
        $crypted = $crypter->encrypt(file_get_contents($origin));
        file_put_contents(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'docker-compose.yml.gpg', $crypted);
        $decrypted = $decrypter->decrypt(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'docker-compose.yml.gpg');
        unlink(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'docker-compose.yml.gpg');

        $this->assertEquals(file_get_contents($origin), $decrypted);
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeFile($crypter, $decrypter)
    {
        $origin = 'docker-compose.yml';
        $crypted = $crypter->encrypt($origin);
        file_put_contents(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'docker-compose.yml.gpg', $crypted);
        $decrypted = $decrypter->decrypt(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'docker-compose.yml.gpg');
        $this->assertEquals(file_get_contents($origin), $decrypted);
        unlink(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'docker-compose.yml.gpg');
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testEncodeDecodeFileText($crypter, $decrypter)
    {
        $origin = 'docker-compose.yml';
        $crypted = $crypter->encrypt($origin);
        $decrypted = $decrypter->decrypt($crypted);
        $this->assertEquals(file_get_contents($origin), $decrypted);
    }

    /**
     * @dataProvider providerCryptoData
     */
    public function testSignVerifyConsoleFile($crypter, $decrypter)
    {
        $origin = 'docker-compose.yml';
        $crypted = $crypter->sign($origin);
        $decrypted = $decrypter->verify($crypted);
        $this->assertEquals(file_get_contents($origin), $decrypted);
    }
}