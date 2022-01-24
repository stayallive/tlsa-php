<?php

namespace Stayallive\TLSA;

use Spatie\Url\Url;
use Stayallive\TLSA\Exceptions\InvalidArgument;

class Builder
{
    public const CERTIFICATE_USAGE_CA                        = 0;
    public const CERTIFICATE_USAGE_SERVICE_CERTIFICATE       = 1;
    public const CERTIFICATE_USAGE_TRUST_ANCHOR_ASSERTION    = 2;
    public const CERTIFICATE_USAGE_DOMAIN_ISSUED_CERTIFICATE = 3;

    public const SELECTOR_CERTIFICATE = 0;
    public const SELECTOR_PUBLIC_KEY  = 1;

    public const MATCHING_TYPE_FULL   = 0;
    public const MATCHING_TYPE_SHA256 = 1;
    public const MATCHING_TYPE_SHA512 = 2;

    /**
     * The protocol we are generating an TLSA record for.
     */
    protected string $protocol;

    /**
     * The domain we are generating an TLSA record for.
     */
    protected string $domain;

    /**
     * The port we are generating an TLSA record for.
     */
    protected int $port;

    /**
     * The certificate usage field.
     */
    protected int $certificateUsage = self::CERTIFICATE_USAGE_DOMAIN_ISSUED_CERTIFICATE;

    /**
     * The selector field.
     */
    protected int $selector = self::SELECTOR_PUBLIC_KEY;

    /**
     * The matching type field.
     */
    protected int $matchingType = self::MATCHING_TYPE_SHA256;

    /**
     * The certificate association data.
     */
    protected ?string $data = null;

    /**
     * TLSA builder constructor.
     */
    public function __construct(string $url, string $protocol = 'tcp')
    {
        if (empty($url)) {
            throw InvalidArgument::domainIsMissing();
        }

        $parsed = Url::fromString(str_starts_with($url, 'http') ? $url : "https://{$url}");

        $this->protocol = $protocol;
        $this->domain   = $parsed->getHost();
        $this->port     = $parsed->getPort() ?? 443;
    }

    public function certificateUsage(int $certificateUsage): static
    {
        $this->certificateUsage = $certificateUsage;

        return $this;
    }

    public function selector(int $selector): static
    {
        $this->selector = $selector;

        return $this;
    }

    public function matchingType(int $matchingType): static
    {
        $this->matchingType = $matchingType;

        return $this;
    }

    public function forCertificate(string $certificate): static
    {
        if ($this->selector === self::SELECTOR_PUBLIC_KEY) {
            return $this->forPublicKey(Util::getPublicKeyFromCertificate($certificate));
        }

        $this->data = $certificate;

        return $this;
    }

    public function forPublicKey(string $publicKey): static
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
        if ($this->data === null) {
            throw InvalidArgument::missingData();
        }

        return "{$this->certificateUsage} {$this->selector} {$this->matchingType} {$this->convertCertificateDataForRecord($this->data)}";
    }

    private function convertCertificateDataForRecord(string $data): string
    {
        $data = Util::convertPemToDer($data);

        return match ($this->matchingType) {
            self::MATCHING_TYPE_FULL   => bin2hex($data),
            self::MATCHING_TYPE_SHA256 => bin2hex(hash('sha256', $data, true)),
            self::MATCHING_TYPE_SHA512 => bin2hex(hash('sha512', $data, true)),
            default                    => throw InvalidArgument::invalidMatchingType(),
        };
    }
}
