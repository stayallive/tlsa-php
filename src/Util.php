<?php

namespace Stayallive\TLSA;

use Stayallive\TLSA\Exceptions\InvalidArgument;

class Util
{
    /**
     * Convert an PEM encoded certificate to DER encoding.
     *
     * @param  string  $pem
     * @return string
     */
    public static function convertPemToDer(string $pem): string
    {
        return base64_decode(str_replace(["\n", "\r"], '', self::stripHeaders($pem)));
    }

    /**
     * Get the public key from a certificate.
     *
     * @param  string  $pem
     * @return string
     */
    public static function getPublicKeyFromCertificate(string $pem): string
    {
        $certificate = @openssl_x509_read($pem);
        $publicKey = @openssl_get_publickey($certificate);
        $publicKeyDetails = @openssl_pkey_get_details($publicKey);

        if (! isset($publicKeyDetails['key'])) {
            throw InvalidArgument::invalidCertificate();
        }

        return $publicKeyDetails['key'];
    }

    /**
     * Strip the headers from an certificate or public key.
     *
     * @param  string  $pem
     * @return string
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
