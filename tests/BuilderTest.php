<?php

namespace Stayallive\TLSA\Test;

use Stayallive\TLSA\Builder;
use PHPUnit\Framework\TestCase;
use Stayallive\TLSA\Exceptions\InvalidArgument;

class BuilderTest extends TestCase
{
    /** @test */
    public function itThrowsAnExceptionIfAnEmptyStringIsPassed(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(InvalidArgument::domainIsMissing()->getMessage());

        new Builder('');
    }

    /** @test */
    public function itDefaultsToHttpsPort(): void
    {
        $builder = new Builder('alexbouma.me');
        $builder->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp', $builder->getRecordDNSName());
    }

    /** @test */
    public function itDetectsPortInDomain(): void
    {
        $builder = new Builder('alexbouma.me:25');
        $builder->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_25._tcp', $builder->getRecordDNSName());
    }

    /** @test */
    public function itChangesProtocol(): void
    {
        $builder = new Builder('alexbouma.me:25', 'udp');
        $builder->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_25._udp', $builder->getRecordDNSName());
    }

    /** @test */
    public function itThrowsAnExceptionIfNoCertificateDataIsPassed(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(InvalidArgument::missingData()->getMessage());

        (new Builder('alexbouma.me'))->getRecord();
    }

    /** @test */
    public function itThrowsAnExceptionIfInvalidCertifiateIsPassed(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(InvalidArgument::invalidCertificate()->getMessage());

        (new Builder('alexbouma.me'))->forCertificate('i_am_no_certificate')->getRecord();
    }

    /** @test */
    public function itThrowsAnExceptionIfInvalidSelectorIsUsed(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(InvalidArgument::invalidSelectorForPublicKey()->getMessage());

        (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_CERTIFICATE)
            ->forPublicKey($this->get_public_key_stub());
    }

    /** @test */
    public function itThrowsAnExceptionIfInvalidMatchingTypeIsUsed(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessage(InvalidArgument::invalidMatchingType()->getMessage());

        (new Builder('alexbouma.me'))
            ->matchingType(4)
            ->forPublicKey($this->get_public_key_stub())
            ->getRecord();
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate300(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_CERTIFICATE)
            ->matchingType(Builder::MATCHING_TYPE_FULL)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 3 0 0 308206353082051da0030201020212033db6b3a14f9afbb87d0752866bcbf10741300d06092a864886f70d01010b0500304a310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074312330210603550403131a4c6574277320456e637279707420417574686f72697479205833301e170d3138303831383139323031325a170d3138313131363139323031325a3017311530130603550403130c616c6578626f756d612e6d6530820122300d06092a864886f70d01010105000382010f003082010a0282010100caaf466cd7ef4387ffddb7644ccff8d8453d5051e77bd5b7653302908e29b17548ad2eaa500bf8c9a7eb60fd2eab9e14f17e572e2c42ef15844fa39e91a62bcabf2b2e76103dee10385657c696bf1aa90b31d56f3026e24341b0ee6b897f752f21f022fb85890483fd793181b5891ac50d4fda45ba9c9732621c0bbb58a9f2da48f371cd53aab05202b4a425ffd180222e9a136b6b5849389a7fcc4a550492965b2c1287ebf57a6ce9d16d532cba65c1c4b5afdec676165b35acc9066efa32f29146de5b7811f19c9474d4364fed41f4d9ab4c8056649f4938c2375b9a32d70dfbe3d9153f580c64a881d8e5e3190e998e5cd8accd9aa167d1c543e4cecd08ad0203010001a382034630820342300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414a95815fc787e637ab536a2f3a217a84e0d1cb620301f0603551d23041830168014a84a6a63047dddbae6d139b7a64565eff3a8eca1306f06082b0601050507010104633061302e06082b060105050730018622687474703a2f2f6f6373702e696e742d78332e6c657473656e63727970742e6f7267302f06082b060105050730028623687474703a2f2f636572742e696e742d78332e6c657473656e63727970742e6f72672f30490603551d1104423040820c616c6578626f756d612e6d65820c616c6578626f756d612e6e6c82107777772e616c6578626f756d612e6d6582107777772e616c6578626f756d612e6e6c3081fe0603551d200481f63081f33008060667810c0102013081e6060b2b0601040182df130101013081d6302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f72673081ab06082b0601050507020230819e0c819b54686973204365727469666963617465206d6179206f6e6c792062652072656c6965642075706f6e2062792052656c79696e67205061727469657320616e64206f6e6c7920696e206163636f7264616e636520776974682074686520436572746966696361746520506f6c69637920666f756e642061742068747470733a2f2f6c657473656e63727970742e6f72672f7265706f7369746f72792f30820104060a2b06010401d6790204020481f50481f200f0007700c1164ae0a772d2d4392dc80ac10770d4f0c49bde991a4840c1fa075164f63360000001654eb1fdeb0000040300483046022100cba0b03379cd00ebff907bc083482809842ad510e9b0cabb75a41b31fff087150221009ec7492aa00846d750785ea7a6f7089be8c74f9bc009e357dba8a6c3c5243bf2007500293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478000001654eb1fe870000040300463044022022c60c0b3948107e3ca3ea7712c3f848fb63ef7ac9b33eb6df1b61398f7a944d02201c4b3a25173b21fd0c8dcea339557737c233c58f54b0f5574796b576230a8b0f300d06092a864886f70d01010b050003820101007517c331cc7375dcd86ae20d36684ce96a25a8ac1d58a566f17f3ea11dcf5c90b04b27ccabba9ed83bcbc6e46194e1314d59822898dbf288bf1596980c1fa98b6943c8e97516f4efc6ccab0eac7d33c0c2f545aa2bcc73dcb78cc0864e950190eeafab9629831d02d616eaa4f292aa17857abf607cad40995622d40b6329727d5c1e788f1c6372273056bcd881c1fad2169ccf6d8ca1e49fc839272ecd206d3c212b816039c1d17834c4a8d9ccc54b2daddac22f5bbf0c4f528176ac7b0d2a06fb54ab9ddf7331360910cc0e52bfe887da307c3caf1d0f8ff65c30a09815699599905399af2f1300f517b29c3ddf798745404b715552e681a539d18843a7f5ce',
            $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate301(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_CERTIFICATE)
            ->matchingType(Builder::MATCHING_TYPE_SHA256)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 3 0 1 8571eec187ab6ba497b1bb9a76a9d9debdea37d92e103d9f84ce15b93a6bf889', $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate302(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_CERTIFICATE)
            ->matchingType(Builder::MATCHING_TYPE_SHA512)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 3 0 2 c5e5218322e1ea08df875a9e4b9b4d0f473609839a79028cee15e876e62977cd3071c7ca8148127137fdfd037c791786aef03bd8c9a001f870cb1aa8258a97cc', $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate310(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_PUBLIC_KEY)
            ->matchingType(Builder::MATCHING_TYPE_FULL)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 3 1 0 30820122300d06092a864886f70d01010105000382010f003082010a0282010100caaf466cd7ef4387ffddb7644ccff8d8453d5051e77bd5b7653302908e29b17548ad2eaa500bf8c9a7eb60fd2eab9e14f17e572e2c42ef15844fa39e91a62bcabf2b2e76103dee10385657c696bf1aa90b31d56f3026e24341b0ee6b897f752f21f022fb85890483fd793181b5891ac50d4fda45ba9c9732621c0bbb58a9f2da48f371cd53aab05202b4a425ffd180222e9a136b6b5849389a7fcc4a550492965b2c1287ebf57a6ce9d16d532cba65c1c4b5afdec676165b35acc9066efa32f29146de5b7811f19c9474d4364fed41f4d9ab4c8056649f4938c2375b9a32d70dfbe3d9153f580c64a881d8e5e3190e998e5cd8accd9aa167d1c543e4cecd08ad0203010001',
            $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate311(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_PUBLIC_KEY)
            ->matchingType(Builder::MATCHING_TYPE_SHA256)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 3 1 1 02fde8bf472ca3b32ad6afbe15104e2c7f3f942828e049e20e0e341cf939ff78', $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate312(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->selector(Builder::SELECTOR_PUBLIC_KEY)
            ->matchingType(Builder::MATCHING_TYPE_SHA512)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 3 1 2 e81fd0b6c5f17d5083ede94efcc41319e58f978f7f734618989535d3331a6ab90c44b55c8e41d5a283625eb5cbd5a1658c586c6df862d9c6b36925016b564cf3', $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate011(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->certificateUsage(Builder::CERTIFICATE_USAGE_CA)
            ->selector(Builder::SELECTOR_PUBLIC_KEY)
            ->matchingType(Builder::MATCHING_TYPE_SHA256)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 0 1 1 02fde8bf472ca3b32ad6afbe15104e2c7f3f942828e049e20e0e341cf939ff78', $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate111(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->certificateUsage(Builder::CERTIFICATE_USAGE_SERVICE_CERTIFICATE)
            ->selector(Builder::SELECTOR_PUBLIC_KEY)
            ->matchingType(Builder::MATCHING_TYPE_SHA256)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 1 1 1 02fde8bf472ca3b32ad6afbe15104e2c7f3f942828e049e20e0e341cf939ff78', $builder->getRecord());
    }

    /** @test */
    public function itBuildsAValidRecordWithCertificate211(): void
    {
        $builder = (new Builder('alexbouma.me'))
            ->certificateUsage(Builder::CERTIFICATE_USAGE_TRUST_ANCHOR_ASSERTION)
            ->selector(Builder::SELECTOR_PUBLIC_KEY)
            ->matchingType(Builder::MATCHING_TYPE_SHA256)
            ->forCertificate($this->get_certificate_stub());

        $this->assertEquals('_443._tcp.alexbouma.me. IN TLSA 2 1 1 02fde8bf472ca3b32ad6afbe15104e2c7f3f942828e049e20e0e341cf939ff78', $builder->getRecord());
    }

    private function get_certificate_stub(): string
    {
        return file_get_contents(__DIR__ . '/stubs/alexbouma_me.crt');
    }

    private function get_public_key_stub(): string
    {
        return file_get_contents(__DIR__ . '/stubs/alexbouma_me.pub');
    }
}
