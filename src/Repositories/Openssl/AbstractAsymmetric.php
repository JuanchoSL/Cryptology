<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl;
use JuanchoSL\Cryptology\Contracts\SignableInterface;
use JuanchoSL\Cryptology\Contracts\VerifyableInterface;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\SimpleSslSign;
use JuanchoSL\Cryptology\Repositories\Openssl\Traits\SimpleSslVerify;


abstract class AbstractAsymmetric extends AbstractOpenssl //implements SignableInterface, VerifyableInterface
{

    //use SimpleSslSign, SimpleSslVerify;

    const OPTION_PADDING = 'padding';

    protected int $padding = OPENSSL_PKCS1_PADDING;

}