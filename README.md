# TSLA RR builder for PHP

[![Latest Version on Packagist](https://img.shields.io/packagist/v/stayallive/tlsa.svg?style=flat-square)](https://packagist.org/packages/stayallive/tlsa)
[![Total Downloads](https://img.shields.io/packagist/dt/stayallive/tlsa.svg?style=flat-square)](https://packagist.org/packages/stayallive/tlsa)

This package contains a class that can generate TLSA resource records.

```php
$tlsa = new Stayallive\TLSA\Builder('alexbouma.me');

$tlsa->forCertificate($pemEncodedCertificate);

$tlsa->getRecord(); // returns the full DNS record

$tlsa->getRecordContents(); // returns the DNS record contents only
```

## Installation

You can install the package via composer:

```bash
composer require stayallive/tlsa
```

## Usage

The class can generate a TLSA resource record for all certificate usages, selectors and matching types.

For more information check out the Wikipedia entry: https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities#RR_data_fields

``` php
use Stayallive\TLSA;

$tlsa = new TLSA\Builder('alexbouma.me', 25, 'udp'); // Builder for the alexbouma.me domain, port 25 and the UDP protocol

$tlsa->forCertificate($pemEncodedCertificate);
$tlsa->forPublicKey($pemEncodedPublicKey);

$tlsa->certificateUsage(TLSA\Builder::CERTIFICATE_USAGE_DOMAIN_ISSUED_CERTIFICATE); // Set the certificate usage to `3` (default)

$tlsa->selector(TLSA\Builder::SELECTOR_PUBLIC_KEY); // Set the selector to `1` (default)

$tlsa->matchingType(TLSA\Builder::MATCHING_TYPE_SHA256); // Set the matching type to `1` (default)

$dns->getRecord(); // returns the full DNS record
$dns->getRecordContents(); // returns the DNS record contents
```

### Testing

``` bash
composer test
```

### Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

### Security

If you discover any security related issues, please email me@alexbouma.me instead of using the issue tracker.

## Credits

- [Alex Bouma](https://github.com/stayallive)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
