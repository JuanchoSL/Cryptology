<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;

use JuanchoSL\Cryptology\AbstractCrypted;
use JuanchoSL\Exceptions\PreconditionRequiredException;

abstract class AbstractOpenssl extends AbstractCrypted
{

    public function __construct(array $options = [])
    {
        if (!extension_loaded('openssl')) {
            throw new PreconditionRequiredException("The extension OPENSSL is not available");
        }
        foreach ($options as $option_name => $option_value) {
            if (property_exists($this, $option_name)) {
                $this->{$option_name} = $option_value;
            }
        }
    }

    protected function error()
    {
        $error = '';
        while (($e = openssl_error_string()) !== false) {
            $error .= $e . PHP_EOL;
        }
        if (!empty($error)) {
            throw new \Exception($error);
        }
    }
}