<?php

namespace Stayallive\TLSA;

use Stayallive\TLSA\Exceptions\InvalidArgument;

class Util
{
    /**
     * Convert an PEM encoded certificate to DER encoding.
     */
    public static function convertPemToDer(string $pem): string
    {
        return base64_decode(str_replace(["\n", "\r"], '', self::stripHeaders($pem)));
    }

    /**
     * Get the public key from a certificate.
     */
    public static function getPublicKeyFromCertificate(string $pem): string
    {
        $certificate = @openssl_x509_read($pem);

        if ($certificate === false) {
            throw InvalidArgument::invalidCertificate();
        }

        $publicKey = @openssl_get_publickey($certificate);

        if ($publicKey === false) {
            throw InvalidArgument::invalidCertificate();
        }

        $publicKeyDetails = @openssl_pkey_get_details($publicKey);

        if (!isset($publicKeyDetails['key'])) {
            throw InvalidArgument::invalidCertificate();
        }

        return $publicKeyDetails['key'];
    }

    /**
     * Strip the headers from an certificate or public key.
     */
    public static function stripHeaders(string $pem): string
    {
        return trim(str_replace([
            '-----BEGIN PUBLIC KEY-----',
            '-----END PUBLIC KEY-----',
            '-----BEGIN CERTIFICATE-----',
            '-----END CERTIFICATE-----',
        ], '', $pem));
    }
}
