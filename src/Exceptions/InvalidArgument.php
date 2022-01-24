<?php

namespace Stayallive\TLSA\Exceptions;

use InvalidArgumentException;

class InvalidArgument extends InvalidArgumentException
{
    public static function missingData(): static
    {
        return new static('Missing certificate data.');
    }

    public static function domainIsMissing(): static
    {
        return new static('A domain name is required.');
    }

    public static function invalidCertificate(): static
    {
        return new static('Invalid certificate provided.');
    }

    public static function invalidMatchingType(): static
    {
        return new static('Invalid matching type.');
    }

    public static function invalidSelectorForPublicKey(): static
    {
        return new static('Invalid selector, cannot encode full certificate with only the public key.');
    }
}
