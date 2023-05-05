<?php

namespace Aws\Sns;

/**
 * @covers Aws\Sns\MessageValidator
 * @covers Aws\Sns\Message
 */
class FunctionalValidationsTest extends \PHPUnit_Framework_TestCase
{
    private static $certificate =
'-----BEGIN CERTIFICATE-----
MIIF1zCCBL+gAwIBAgIQB9pYWG3Mi7xej22g9pobJTANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0yMTA5MDcwMDAwMDBaFw0yMjA4MTcy
MzU5NTlaMBwxGjAYBgNVBAMTEXNucy5hbWF6b25hd3MuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAutFqueT3XgP13udzxE6UpbdjOtVO5DwoMpSM
iDNMnGzF1TYH5/R2LPUOBeTB0SkKnR4kpNcUZhicpGD4aKciz/GEZ6wu65xncfT9
H/KBOQwoXYTuClHwp6fYpGzcGFaFoEYMnijL/o4qmTSd+ukglQUgKpsDw4ofw6rU
m2CttJo+GQSNQ9NfGR1h/0J+zsApkeSYrXRx5wNlu87z8os1C/6PBrUHwt3xXeaf
Xzfwut8aRRYsS8BySOA9DAgLfNHlfdQCjKPXKrG/ussgReyWD6n/HH+j7Uha3xos
TzQqJifcxlTq6MxWdPR6fDaJNvqw6DOE7UjUNxHguXHlVfxhlQIDAQABo4IC6TCC
AuUwHwYDVR0jBBgwFoAUWaRmBlKge5WSPKOUByeWdFv5PdAwHQYDVR0OBBYEFAqz
C+vyouneE7mWWLbi9i0UsWUbMBwGA1UdEQQVMBOCEXNucy5hbWF6b25hd3MuY29t
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
OwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybC5zY2ExYi5hbWF6b250cnVzdC5j
b20vc2NhMWIuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkw
ZzAtBggrBgEFBQcwAYYhaHR0cDovL29jc3Auc2NhMWIuYW1hem9udHJ1c3QuY29t
MDYGCCsGAQUFBzAChipodHRwOi8vY3J0LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9z
Y2ExYi5jcnQwDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFn
AHYAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF7vfDVkQAABAMA
RzBFAiEA2XfHuy36aqRFiaL8c3md2mH451go8707+fRE0pEdSRACIE/g5FXTUXUZ
PFcmOhm9TZ+uMY1i4CIQ/CKVWln6C3t+AHYAUaOw9f0BeZxWbbg3eI8MpHrMGyfL
956IQpoN/tSLBeUAAAF7vfDVjAAABAMARzBFAiBF1MhhFP0+FQt3daDFfMYoWwnr
muTInrjNpwfzlvQBugIhAPYadFzr+LaxSJoiZEbEHBvTts7bT0M3eCQONA2O7w6n
AHUAQcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF7vfDVdAAABAMA
RjBEAiAtPapmFAuA71ih4NoSd5hJelzAltNQpxDMcDfDyHyU8gIgWxmaa6+2KbBu
9xdv379zvnJACFR7jc+4asl08Dn4aagwDQYJKoZIhvcNAQELBQADggEBAA54QX0u
oFWXfMmv02CGZv4NWo5TapyeeixQ2kKpZHRdVZjxZrw+hoF6HD7P3kGjH8ztyJll
tDxB0qgMltbPhQdScwhA6iTgoaBYqEUC/VHKd4PmmPT6yIsM36NBZVmkGlzl5uNo
/dBgBaG0SsVJnhr5zro3c2quC7n6fVGEZhf/UgQwRnnvThnvbNKguglDMq4uEqv8
njKyleht+glkcmXO0m9qLKt6BOS0amy6U2GlAwRn0Wx02ndJtnRCSC6kPuRWK/SQ
FEjB7gCK4hdKaAOuWdZpI55vF6ifOeM8toC3g7ofO8qLTnJupAG+ZitY5J3cvHWr
HqOUdKigPDHYLRo=
-----END CERTIFICATE-----';

    public function getHttpFixtures()
    {
        return [
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "792cda85-518f-5dd3-9163-81d851212f3a",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-892f85fe-4836-424d-8188-ab85bef0f362",
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T21:23:58.317Z",
                    'SignatureVersion' => "1",
                    'Signature' => "ghtf+deOBAzHJJZ6s6CdRLfTQAlcGzq9naoFM1wi0CJiq//uVRuZnamrkWNF0fhouMFvuLVRwcz8PZLUMSfnmd5VpdTKpTyiKmy1qJAZXma0w+yi7G+I33hD1Jyk1Nbym2n0kqp3fVu2aoooiN2ZeLAT2bH0/BtjLSfN1yAOKNoprco4qV9gGUZinXJdj9a1YdNhDR2jKi33ldlsVtEXAtiaDklGEk7DgRKX38GerBPiLg3FdtgY6KC7cdeGpU/dGK+4hjc83Ive1HoFkAwqhpgInM2sMytBosoiXfCmOKmU4xeGD0gHDNZTlJUJQDlzw8Eag0H9f/5zXF9d3uy0YQ==",
                    'SigningCertURL' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeURL' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-892f85fe-4836-424d-8188-ab85bef0f362:2296bc94-7992-4be1-b15f-b97229b5c1d8",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "17dea24b-55c2-540b-8362-f916557af765",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-62674b1d-4295-426b-88e7-5fb75652a04e",
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T21:24:08.324Z",
                    'SignatureVersion' => "2",
                    'Signature' => "CXVqp9PfZAL+4JHS3Zxo1PFbQsvnOjvmYhtIf17TWpwc+iIVas8kZ8GopuzVzVMdatE7rCl/O4P91Zp05Dwz8lk8dLhfp8gSu3Njlzxlyrmzo9x3va3Jb7zFnedgS2GKnZWHGBdwTXho+TosNUE+3e10OMSlwN5XGDwX7+R3WL+rn+AXmFAqp3alg27sYa55h1dLE9cGszGPjScPdtF3BmZsUDMx9wSdNKsCk+vSvE8yBjnCmUl7laSFj3LzPVrlSwgNYCF3kYnNAkah7NplK4SFhJYLwS0HCVCQJKa8rVbQLf9cBTu60U402mrgy0bN8xWoyimzbYbrOMJjalqkUg==",
                    'SigningCertURL' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeURL' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-62674b1d-4295-426b-88e7-5fb75652a04e:ad7d16e3-0a7c-46aa-b23e-ffaf02250cbe",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "11405cc3-9ac7-56d5-b45d-079e8f7a8edf",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-6e11fed2-fcdf-4c52-9dc4-36ef43f37f84",
                    'Subject' => "Hello world",
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T22:53:49.654Z",
                    'SignatureVersion' => "1",
                    'Signature' => "AItkS26d8yvnIKJevdirIPW7eM/yKbZy3/CF2EreCHmXWB3etWaV5Fb7SYpGABMpugpDZzNyGY1wCVWaopDoQ+7Q/kI2TpDu8bw1eExbi8U3kduvc/2m2fIrI4gDEY8/v3nzoLcr8pPodqMzrX6SzQou4klfaqbNK+rFmH0LVf2Q1VyOROODoSXmo4jg2Yu12jfxccBl96Drr/ihq4MJ4OcrWh6UzXXlVYjJHx2Ui4anNwNEb+Z4C2CAF1DjQUbhDtaoajDBPY+4d9C1OwbqwQpXsd6tyVcI9nFyEsVK8lfnAV+/3GZQcdXHbIUYBRGcBa4X5TlWJku5nDH2ERtHHw==",
                    'SigningCertURL' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeURL' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-6e11fed2-fcdf-4c52-9dc4-36ef43f37f84:adb318c3-2234-4c56-905d-c324cf0df874",
                ]
            ],
            [
                [
                  'Type' => "Notification",
                  'MessageId' => "4504e649-d933-5aa9-8199-bd14ccf05f0b",
                  'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-530b26da-0687-4fe4-9f71-780bad3181e2",
                  'Subject' => "Hello world",
                  'Message' => "Hello world",
                  'Timestamp' => "2022-07-28T22:53:55.086Z",
                  'SignatureVersion' => "2",
                  'Signature' => "cETcSvmmkt+My05qCLKexyl0+RyG83mSryKPqTfS+tYcxDJWVcjPJAr+qdpElzVaBl1aTGYVWMY64i9JqZ/JES8pylNj8LGvdhuNQKO59/WCoIimZAsNhn0xEgOeeDU+W/0BU4sdpCGMNjo0S/FuIiWaRe4E0YWRVrxeQevaQ70euDdfWgd5v1eCKQz8b367b9XBmMztL/CWUFI6YaKK/MV21eyvJe3Y7CtVYiOKEYiAZnAEkynK7gUGO5TsgDjGNYhj6U3xYsWgI03bmioSl7kdFSUj+AZ7ugas5fghqxgoDsdfqsjMYKRm5KKHQWsgzI619yIzpNKUiSMHxdZXpQ==",
                  'SigningCertURL' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                  'UnsubscribeURL' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-530b26da-0687-4fe4-9f71-780bad3181e2:db0ad2ad-03d1-48ca-a5da-51f317800a57"
                ]
            ]
        ];
    }

    public function getLambdaFixtures()
    {
        return [
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "792cda85-518f-5dd3-9163-81d851212f3a",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-892f85fe-4836-424d-8188-ab85bef0f362",
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T21:23:58.317Z",
                    'SignatureVersion' => "1",
                    'Signature' => "ghtf+deOBAzHJJZ6s6CdRLfTQAlcGzq9naoFM1wi0CJiq//uVRuZnamrkWNF0fhouMFvuLVRwcz8PZLUMSfnmd5VpdTKpTyiKmy1qJAZXma0w+yi7G+I33hD1Jyk1Nbym2n0kqp3fVu2aoooiN2ZeLAT2bH0/BtjLSfN1yAOKNoprco4qV9gGUZinXJdj9a1YdNhDR2jKi33ldlsVtEXAtiaDklGEk7DgRKX38GerBPiLg3FdtgY6KC7cdeGpU/dGK+4hjc83Ive1HoFkAwqhpgInM2sMytBosoiXfCmOKmU4xeGD0gHDNZTlJUJQDlzw8Eag0H9f/5zXF9d3uy0YQ==",
                    'SigningCertUrl' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeUrl' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-892f85fe-4836-424d-8188-ab85bef0f362:2296bc94-7992-4be1-b15f-b97229b5c1d8",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "17dea24b-55c2-540b-8362-f916557af765",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-62674b1d-4295-426b-88e7-5fb75652a04e",
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T21:24:08.324Z",
                    'SignatureVersion' => "2",
                    'Signature' => "CXVqp9PfZAL+4JHS3Zxo1PFbQsvnOjvmYhtIf17TWpwc+iIVas8kZ8GopuzVzVMdatE7rCl/O4P91Zp05Dwz8lk8dLhfp8gSu3Njlzxlyrmzo9x3va3Jb7zFnedgS2GKnZWHGBdwTXho+TosNUE+3e10OMSlwN5XGDwX7+R3WL+rn+AXmFAqp3alg27sYa55h1dLE9cGszGPjScPdtF3BmZsUDMx9wSdNKsCk+vSvE8yBjnCmUl7laSFj3LzPVrlSwgNYCF3kYnNAkah7NplK4SFhJYLwS0HCVCQJKa8rVbQLf9cBTu60U402mrgy0bN8xWoyimzbYbrOMJjalqkUg==",
                    'SigningCertUrl' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeUrl' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-62674b1d-4295-426b-88e7-5fb75652a04e:ad7d16e3-0a7c-46aa-b23e-ffaf02250cbe",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "792cda85-518f-5dd3-9163-81d851212f3a",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-892f85fe-4836-424d-8188-ab85bef0f362",
                    'Subject' => null,
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T21:23:58.317Z",
                    'SignatureVersion' => "1",
                    'Signature' => "ghtf+deOBAzHJJZ6s6CdRLfTQAlcGzq9naoFM1wi0CJiq//uVRuZnamrkWNF0fhouMFvuLVRwcz8PZLUMSfnmd5VpdTKpTyiKmy1qJAZXma0w+yi7G+I33hD1Jyk1Nbym2n0kqp3fVu2aoooiN2ZeLAT2bH0/BtjLSfN1yAOKNoprco4qV9gGUZinXJdj9a1YdNhDR2jKi33ldlsVtEXAtiaDklGEk7DgRKX38GerBPiLg3FdtgY6KC7cdeGpU/dGK+4hjc83Ive1HoFkAwqhpgInM2sMytBosoiXfCmOKmU4xeGD0gHDNZTlJUJQDlzw8Eag0H9f/5zXF9d3uy0YQ==",
                    'SigningCertUrl' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeUrl' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-892f85fe-4836-424d-8188-ab85bef0f362:2296bc94-7992-4be1-b15f-b97229b5c1d8",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "17dea24b-55c2-540b-8362-f916557af765",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-62674b1d-4295-426b-88e7-5fb75652a04e",
                    'Subject' => null,
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T21:24:08.324Z",
                    'SignatureVersion' => "2",
                    'Signature' => "CXVqp9PfZAL+4JHS3Zxo1PFbQsvnOjvmYhtIf17TWpwc+iIVas8kZ8GopuzVzVMdatE7rCl/O4P91Zp05Dwz8lk8dLhfp8gSu3Njlzxlyrmzo9x3va3Jb7zFnedgS2GKnZWHGBdwTXho+TosNUE+3e10OMSlwN5XGDwX7+R3WL+rn+AXmFAqp3alg27sYa55h1dLE9cGszGPjScPdtF3BmZsUDMx9wSdNKsCk+vSvE8yBjnCmUl7laSFj3LzPVrlSwgNYCF3kYnNAkah7NplK4SFhJYLwS0HCVCQJKa8rVbQLf9cBTu60U402mrgy0bN8xWoyimzbYbrOMJjalqkUg==",
                    'SigningCertUrl' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeUrl' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-62674b1d-4295-426b-88e7-5fb75652a04e:ad7d16e3-0a7c-46aa-b23e-ffaf02250cbe",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "11405cc3-9ac7-56d5-b45d-079e8f7a8edf",
                    'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-6e11fed2-fcdf-4c52-9dc4-36ef43f37f84",
                    'Subject' => "Hello world",
                    'Message' => "Hello world",
                    'Timestamp' => "2022-07-28T22:53:49.654Z",
                    'SignatureVersion' => "1",
                    'Signature' => "AItkS26d8yvnIKJevdirIPW7eM/yKbZy3/CF2EreCHmXWB3etWaV5Fb7SYpGABMpugpDZzNyGY1wCVWaopDoQ+7Q/kI2TpDu8bw1eExbi8U3kduvc/2m2fIrI4gDEY8/v3nzoLcr8pPodqMzrX6SzQou4klfaqbNK+rFmH0LVf2Q1VyOROODoSXmo4jg2Yu12jfxccBl96Drr/ihq4MJ4OcrWh6UzXXlVYjJHx2Ui4anNwNEb+Z4C2CAF1DjQUbhDtaoajDBPY+4d9C1OwbqwQpXsd6tyVcI9nFyEsVK8lfnAV+/3GZQcdXHbIUYBRGcBa4X5TlWJku5nDH2ERtHHw==",
                    'SigningCertUrl' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                    'UnsubscribeUrl' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-6e11fed2-fcdf-4c52-9dc4-36ef43f37f84:adb318c3-2234-4c56-905d-c324cf0df874",
                ]
            ],
            [
                [
                  'Type' => "Notification",
                  'MessageId' => "4504e649-d933-5aa9-8199-bd14ccf05f0b",
                  'TopicArn' => "arn:aws:sns:us-east-2:295079676684:publish-and-verify-530b26da-0687-4fe4-9f71-780bad3181e2",
                  'Subject' => "Hello world",
                  'Message' => "Hello world",
                  'Timestamp' => "2022-07-28T22:53:55.086Z",
                  'SignatureVersion' => "2",
                  'Signature' => "cETcSvmmkt+My05qCLKexyl0+RyG83mSryKPqTfS+tYcxDJWVcjPJAr+qdpElzVaBl1aTGYVWMY64i9JqZ/JES8pylNj8LGvdhuNQKO59/WCoIimZAsNhn0xEgOeeDU+W/0BU4sdpCGMNjo0S/FuIiWaRe4E0YWRVrxeQevaQ70euDdfWgd5v1eCKQz8b367b9XBmMztL/CWUFI6YaKK/MV21eyvJe3Y7CtVYiOKEYiAZnAEkynK7gUGO5TsgDjGNYhj6U3xYsWgI03bmioSl7kdFSUj+AZ7ugas5fghqxgoDsdfqsjMYKRm5KKHQWsgzI619yIzpNKUiSMHxdZXpQ==",
                  'SigningCertUrl' => "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                  'UnsubscribeUrl' => "https://sns.us-east-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:295079676684:publish-and-verify-530b26da-0687-4fe4-9f71-780bad3181e2:db0ad2ad-03d1-48ca-a5da-51f317800a57"
                ]
            ]
        ];
    }

    private function getMockCertServerClient()
    {
        return function () {
            return self::$certificate;
        };
    }

    /**
     * @dataProvider getHttpFixtures
     *
     * @param array $messageData
     */
    public function testValidatesHttpFixtures($messageData)
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = new Message($messageData);

        $this->assertTrue($validator->isValid($message));
        $this->assertNotEmpty($message['SigningCertURL']);
    }

    /**
     * @dataProvider getLambdaFixtures
     *
     * @param array $messageData
     */
    public function testValidatesLambdaFixtures($messageData)
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = new Message($messageData);

        $this->assertTrue($validator->isValid($message));
        $this->assertNotEmpty($message['SigningCertUrl']);
    }
}
