# Amazon SNS Message Validator for PHP

[![@awsforphp on Twitter](http://img.shields.io/badge/twitter-%40awsforphp-blue.svg?style=flat)](https://twitter.com/awsforphp)
[![Total Downloads](https://img.shields.io/packagist/dt/aws/aws-php-sns-message-validator.svg?style=flat)](https://packagist.org/packages/aws/aws-php-sns-message-validator)
[![Build Status](https://img.shields.io/travis/aws/aws-php-sns-message-validator.svg?style=flat)](https://travis-ci.org/aws/aws-php-sns-message-validator)
[![Apache 2 License](https://img.shields.io/packagist/l/aws/aws-php-sns-message-validator.svg?style=flat)](http://aws.amazon.com/apache-2-0/)

The **Amazon SNS Message Validator for PHP** library allows you to validate that
incoming HTTP(S) POST messages are valid Amazon SNS notifications. This library
is standalone and does not depend on the AWS SDK for PHP or Guzzle; however, it
does require PHP 5.4+ and that the OpenSSL PHP extension is installed.

Jump To:
* [Basic Usage](_#Basic-Usage_)
* [Installation](_#Installation_)
* [About Amazon SNS](_#About-Amazon-SNS_)
* [Handling Messages](_#Handling-Messages_)
* [Testing Locally](_#Testing-Locally_)
* [Contributing](_#Contributing_)

## Basic Usage

To validate a message, you can instantiate a `Message` object from the POST
data using the `Message::fromRawPostData`. This reads the raw POST data from
the [`php://input` stream][php-input], decodes the JSON data, and validates
the message's type and structure.

Next, you must create an instance of `MessageValidator`, and then use either
the `isValid()` or `validate()`, methods to validate the message. The
message validator checks the `SigningCertURL`, `SignatureVersion`, and
`Signature` to make sure they are valid and consistent with the message data.

```php
<?php

require 'vendor/autoload.php';

use Aws\Sns\Message;
use Aws\Sns\MessageValidator;
 
$message = Message::fromRawPostData();
 
// Validate the message
$validator = new MessageValidator();
if ($validator->isValid($message)) {
   // do something with the message
}
```

## Installation

The SNS Message Validator can be installed via [Composer][].

    $ composer require aws/aws-php-sns-message-validator

## Getting Help

Please use these community resources for getting help. We use the GitHub issues for tracking bugs and feature requests and have limited bandwidth to address them.

* Ask a question on [StackOverflow](https://stackoverflow.com/) and tag it with [`aws-php-sdk`](http://stackoverflow.com/questions/tagged/aws-php-sdk)
* Come join the AWS SDK for PHP [gitter](https://gitter.im/aws/aws-sdk-php)
* Open a support ticket with [AWS Support](https://console.aws.amazon.com/support/home/)
* If it turns out that you may have found a bug, please [open an issue](https://github.com/aws/aws-php-sns-message-validator/issues/new/choose)

## About Amazon SNS

[Amazon Simple Notification Service (Amazon SNS)][sns] is a fast, fully-managed,
push messaging service. Amazon SNS can deliver messages to email, mobile devices
(i.e., SMS; iOS, Android and FireOS push notifications), Amazon SQS queues,and
— of course — HTTP/HTTPS endpoints.

With Amazon SNS, you can setup topics to publish custom messages to subscribed
endpoints. However, SNS messages are used by many of the other AWS services to
communicate information asynchronously about your AWS resources. Some examples
include:

* Configuring Amazon Glacier to notify you when a retrieval job is complete.
* Configuring AWS CloudTrail to notify you when a new log file has been written.
* Configuring Amazon Elastic Transcoder to notify you when a transcoding job
  changes status (e.g., from "Progressing" to "Complete")

Though you can certainly subscribe your email address to receive SNS messages
from service events like these, your inbox would fill up rather quickly. There
is great power, however, in being able to subscribe an HTTP/HTTPS endpoint to
receive the messages. This allows you to program webhooks for your applications
to easily respond to various events.

## Handling Messages

### Confirming a Subscription to a Topic

In order to handle a `SubscriptionConfirmation` message, you must use the
`SubscribeURL` value in the incoming message:

```php
use Aws\Sns\Message;
use Aws\Sns\MessageValidator;
use Aws\Sns\Exception\InvalidSnsMessageException;

// Instantiate the Message and Validator
$message = Message::fromRawPostData();
$validator = new MessageValidator();

// Validate the message and log errors if invalid.
try {
   $validator->validate($message);
} catch (InvalidSnsMessageException $e) {
   // Pretend we're not here if the message is invalid.
   http_response_code(404);
   error_log('SNS Message Validation Error: ' . $e->getMessage());
   die();
}

// Check the type of the message and handle the subscription.
if ($message['Type'] === 'SubscriptionConfirmation') {
   // Confirm the subscription by sending a GET request to the SubscribeURL
   file_get_contents($message['SubscribeURL']);
}
```

### Receiving a Notification

To receive a notification, use the same code as the preceding example, but
check for the `Notification` message type.

```php
if ($message['Type'] === 'Notification') {
   // Do whatever you want with the message body and data.
   echo $message['MessageId'] . ': ' . $message['Message'] . "\n";
}
```

The message body will be a string, and will hold whatever data was published
to the SNS topic.

### Unsubscribing

Unsubscribing looks the same as subscribing, except the message type will be
`UnsubscribeConfirmation`.

```php
if ($message['Type'] === 'UnsubscribeConfirmation') {
    // Unsubscribed in error? You can resubscribe by visiting the endpoint
    // provided as the message's SubscribeURL field.
    file_get_contents($message['SubscribeURL']);
}
```

## Testing Locally

One challenge of using webhooks in a web application is testing the integration
with the service. Testing integrations with SNS notifications can be fairly easy
using tools like [ngrok][] and [PHP's built-in webserver][php-server]. One of
our blog posts, [*Testing Webhooks Locally for Amazon SNS*][blogpost], illustrates
a good technique for testing.

> **NOTE:** The code samples in the blog post are specific to the message
> validator in Version 2 of the SDK, but can be easily adapted to using this
> version.

### Special Thank You

A special thanks goes out to [Julian Vidal][] who helped create the [initial
implementation][] in Version 2 of the [AWS SDK for PHP][].

[php-input]: http://php.net/manual/en/wrappers.php.php#wrappers.php.input
[composer]: https://getcomposer.org/
[source code]: https://github.com/aws/aws-php-sns-message-validator/archive/master.zip
[sns]: http://aws.amazon.com/sns/
[ngrok]: https://ngrok.com/
[php-server]: http://www.php.net/manual/en/features.commandline.webserver.php
[blogpost]: http://blogs.aws.amazon.com/php/post/Tx2CO24DVG9CAK0/Testing-Webhooks-Locally-for-Amazon-SNS
[Julian Vidal]: https://github.com/poisa
[initial implementation]: https://github.com/aws/aws-sdk-php/tree/2.8/src/Aws/Sns/MessageValidator
[AWS SDK for PHP]: https://github.com/aws/aws-sdk-php

## Contributing

We work hard to provide a high-quality and useful SDK for our AWS services, and we greatly value feedback and contributions from our community. Please review our [contributing guidelines](./CONTRIBUTING.md) before submitting any issues or pull requests to ensure we have all the necessary information to effectively respond to your bug report or contribution.