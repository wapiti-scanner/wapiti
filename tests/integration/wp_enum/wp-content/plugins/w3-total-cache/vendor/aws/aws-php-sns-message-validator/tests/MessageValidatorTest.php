<?php
namespace Aws\Sns;

/**
 * @covers Aws\Sns\MessageValidator
 */
class MessageValidatorTest extends \PHPUnit_Framework_TestCase
{
    const VALID_CERT_URL = 'https://sns.foo.amazonaws.com/bar.pem';

    private static $pKey;
    private static $certificate;

    public static function setUpBeforeClass()
    {
        self::$pKey = openssl_pkey_new();
        $csr = openssl_csr_new([], self::$pKey);
        $x509 = openssl_csr_sign($csr, null, self::$pKey, 1);
        openssl_x509_export($x509, self::$certificate);
        openssl_x509_free($x509);
    }

    public static function tearDownAfterClass()
    {
        openssl_pkey_free(self::$pKey);
    }

    public function testIsValidReturnsFalseOnFailedValidation()
    {
        $validator = new MessageValidator($this->getMockHttpClient());
        $message = $this->getTestMessage([
            'SignatureVersion' => '2',
        ]);
        $this->assertFalse($validator->isValid($message));
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage The SignatureVersion "3" is not supported.
     */
    public function testValidateFailsWhenSignatureVersionIsInvalid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'SignatureVersion' => '3',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage The certificate is located on an invalid domain.
     */
    public function testValidateFailsWhenCertUrlInvalid()
    {
        $validator = new MessageValidator();
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar.pem',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage The certificate is located on an invalid domain.
     */
    public function testValidateFailsWhenCertUrlNotAPemFile()
    {
        $validator = new MessageValidator();
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar',
        ]);
        $validator->validate($message);
    }

    public function testValidatesAgainstCustomDomains()
    {
        $validator = new MessageValidator(
            function () {
                return self::$certificate;
            },
            '/^(foo|bar).example.com$/'
        );
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.example.com/baz.pem',
        ]);
        $message['Signature'] = $this->getSignature($validator->getStringToSign($message));
        $this->assertTrue($validator->isValid($message));
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessageRegExp /Cannot get the certificate from ".+"./
     */
    public function testValidateFailsWhenCannotGetCertificate()
    {
        $validator = new MessageValidator($this->getMockHttpClient(false));
        $message = $this->getTestMessage();
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage Cannot get the public key from the certificate.
     */
    public function testValidateFailsWhenCannotDeterminePublicKey()
    {
        $validator = new MessageValidator($this->getMockHttpClient());
        $message = $this->getTestMessage();
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage The message signature is invalid.
     */
    public function testValidateFailsWhenMessageIsInvalid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'Signature' => $this->getSignature('foo'),
        ]);
        $validator->validate($message);
    }

        /**
         * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
         * @expectedExceptionMessage The message signature is invalid.
         */
        public function testValidateFailsWhenSha256MessageIsInvalid()
        {
            $validator = new MessageValidator($this->getMockCertServerClient());
            $message = $this->getTestMessage([
                'Signature' => $this->getSignature('foo'),
                 'SignatureVersion' => '2'

            ]);
            $validator->validate($message);
        }

    public function testValidateSucceedsWhenMessageIsValid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage();

        // Get the signature for a real message
        $message['Signature'] = $this->getSignature($validator->getStringToSign($message));

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    public function testValidateSucceedsWhenSha256MessageIsValid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'SignatureVersion' => '2'
        ]);

        // Get the signature for a real message
        $message['Signature'] = $this->getSignature($validator->getStringToSign($message), '2');

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    public function testBuildsStringToSignCorrectly()
    {
        $validator = new MessageValidator();
        $stringToSign = <<< STRINGTOSIGN
Message
foo
MessageId
bar
Timestamp
1435697129
TopicArn
baz
Type
Notification

STRINGTOSIGN;

        $this->assertEquals(
            $stringToSign,
            $validator->getStringToSign($this->getTestMessage())
        );
    }

    /**
     * @param array $customData
     *
     * @return Message
     */
    private function getTestMessage(array $customData = [])
    {
        return new Message($customData + [
            'Message'          => 'foo',
            'MessageId'        => 'bar',
            'Timestamp'        => time(),
            'TopicArn'         => 'baz',
            'Type'             => 'Notification',
            'SigningCertURL'   => self::VALID_CERT_URL,
            'Signature'        => true,
            'SignatureVersion' => '1',
        ]);
    }

    private function getMockHttpClient($responseBody = '')
    {
        return function () use ($responseBody) {
            return $responseBody;
        };
    }

    private function getMockCertServerClient()
    {
        return function ($url) {
            if ($url !== self::VALID_CERT_URL) {
                return '';
            }

            return self::$certificate;
        };
    }

    private function getSignature($stringToSign, $algo = '1')
    {
        if ($algo === '2') {
            openssl_sign($stringToSign, $signature, self::$pKey, 'SHA256');
        } else {
            openssl_sign($stringToSign, $signature, self::$pKey);
        }

        return base64_encode($signature);
    }
}

function time()
{
    return 1435697129;
}
