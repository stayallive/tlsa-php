<?php

namespace Stayallive\TLSA\Exceptions;

use InvalidArgumentException;

class InvalidArgument extends InvalidArgumentException
{
    public static function missingData()
    {
        return new static('Missing certificate data.');
    }

    public static function domainIsMissing()
    {
        return new static('A domain name is required.');
    }

    public static function invalidCertificate()
    {
        return new static('Invalid certificate provided.');
    }

    public static function invalidMatchingType()
    {
        return new static('Invalid matching type.');
    }

    public static function invalidSelectorForPublicKey()
    {
        return new static('Invalid selector, cannot encode full certificate with only the public key.');
    }
}
