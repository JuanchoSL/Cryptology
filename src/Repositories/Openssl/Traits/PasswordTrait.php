<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology\Repositories\Openssl\Traits;

trait PasswordTrait
{

    protected string $password;

    public function setPassword(string $password): static
    {
        $this->password = $password;
        return $this;
    }

}