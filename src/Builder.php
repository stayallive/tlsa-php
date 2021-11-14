<?php

namespace Stayallive\TLSA;

use Spatie\Url\Url;
use Stayallive\TLSA\Exceptions\InvalidArgument;

class Builder
{
    public const CERTIFICATE_USAGE_CA = 0;
    public const CERTIFICATE_USAGE_SERVICE_CERTIFICATE = 1;
    public const CERTIFICATE_USAGE_TRUST_ANCHOR_ASSERTION = 2;
    public const CERTIFICATE_USAGE_DOMAIN_ISSUED_CERTIFICATE = 3;

    public const SELECTOR_CERTIFICATE = 0;
    public const SELECTOR_PUBLIC_KEY = 1;

    public const MATCHING_TYPE_FULL = 0;
    public const MATCHING_TYPE_SHA256 = 1;
    public const MATCHING_TYPE_SHA512 = 2;

    /**
     * The protocol we are generating an TLSA record for.
     *
     * @var string
     */
    protected $protocol;

    /**
     * The domain we are generating an TLSA record for.
     *
     * @var string
     */
    protected $domain;

    /**
     * The port we are generating an TLSA record for.
     *
     * @var int
     */
    protected $port;

    /**
     * The certificate usage field.
     *
     * @var int
     */
    protected $certificate_usage;

    /**
     * The selector field.
     *
     * @var int
     */
    protected $selector;

    /**
     * The matching type field.
     *
     * @var int
     */
    protected $matching_type;

    /**
     * The certificate association data.
     *
     * @var string
     */
    protected $data;

    /**
     * TLSA constructor.
     *
     * @param  string  $url
     * @param  string  $protocol
     */
    public function __construct(string $url, string $protocol = 'tcp')
    {
        if (empty($url)) {
            throw InvalidArgument::domainIsMissing();
        }

        $parsed = Url::fromString(strpos($url, 'http') === 0 ? $url : "https://{$url}");

        $this->protocol = $protocol;
        $this->domain = $parsed->getHost();
        $this->port = $parsed->getPort() ?? 443;

        // Set some default values
        $this->certificate_usage = self::CERTIFICATE_USAGE_DOMAIN_ISSUED_CERTIFICATE;
        $this->selector = self::SELECTOR_PUBLIC_KEY;
        $this->matching_type = self::MATCHING_TYPE_SHA256;
    }

    public function certificateUsage(int $certificateUsage)
    {
        $this->certificate_usage = $certificateUsage;

        return $this;
    }

    public function selector(int $selector)
    {
        $this->selector = $selector;

        return $this;
    }

    public function matchingType(int $matchingType)
    {
        $this->matching_type = $matchingType;

        return $this;
    }

    public function forCertificate(string $certificate)
    {
        if ($this->selector === self::SELECTOR_PUBLIC_KEY) {
            return $this->forPublicKey(Util::getPublicKeyFromCertificate($certificate));
        }

        $this->data = $certificate;

        return $this;
    }

    public function forPublicKey(string $publicKey)
    {
        if ($this->selector === self::SELECTOR_CERTIFICATE) {
            throw InvalidArgument::invalidSelectorForPublicKey();
        }

        $this->data = $publicKey;

        return $this;
    }

    public function getRecord(): string
    {
        return "{$this->getRecordFullDNSName()}. IN TLSA {$this->getRecordContents()}";
    }

    public function getRecordDNSName(): string
    {
        return "_{$this->port}._{$this->protocol}";
    }

    public function getRecordFullDNSName(): string
    {
        return "{$this->getRecordDNSName()}.{$this->domain}";
    }

    public function getRecordContents(): string
    {
        if (empty($this->data)) {
            throw InvalidArgument::missingData();
        }

        return "{$this->certificate_usage} {$this->selector} {$this->matching_type} {$this->convertCertificateDataForRecord($this->data)}";
    }

    private function convertCertificateDataForRecord(string $data): string
    {
        $data = Util::convertPemToDer($data);

        switch ($this->matching_type) {
            case self::MATCHING_TYPE_FULL:
                return bin2hex($data);
            case self::MATCHING_TYPE_SHA256:
                return bin2hex(hash('sha256', $data, true));
            case self::MATCHING_TYPE_SHA512:
                return bin2hex(hash('sha512', $data, true));
            default:
                throw InvalidArgument::invalidMatchingType();
        }
    }
}
