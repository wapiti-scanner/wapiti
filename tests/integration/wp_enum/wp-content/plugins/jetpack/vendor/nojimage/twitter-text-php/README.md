# Twitter Text (PHP Edition) #

A library of PHP classes that provide auto-linking and extraction of usernames,
lists, hashtags and URLs from tweets.  Originally created from twitter-text-rb
and twitter-text-java projects by Matt Sanford and ported to PHP by Mike
Cochrane, this library has been improved and made more complete by Nick Pope.

<p align="center">
    <a href="https://github.com/nojimage/twitter-text-php/actions/workflows/ci.yml" target="_blank">
        <img alt="Build Status" src="https://github.com/nojimage/twitter-text-php/actions/workflows/ci.yml/badge.svg">
    </a>
    <a href="https://codecov.io/gh/nojimage/twitter-text-php" target="_blank">
        <img alt="Codecov" src="https://img.shields.io/codecov/c/github/nojimage/twitter-text-php.svg?style=flat-square">
    </a>
    <a href="https://packagist.org/packages/nojimage/twitter-text-php" target="_blank">
        <img alt="Latest Stable Version" src="https://img.shields.io/packagist/v/nojimage/twitter-text-php.svg?style=flat-square">
    </a>
</p>

## Requirements ##

- PHP 5.3 or higher
- ext-mbstring
- ext-intl

If the necessary extensions are not installed on the server, please install it additionally or use [symfony/polyfill](https://github.com/symfony/polyfill).

## Install ##

You can install this library into your application using [Composer](https://getcomposer.org/).

```
composer require nojimage/twitter-text-php
```

### Note for Older Server ###

This library use intl/libICU.
Some older server and PHP 7.2+ combinations may have deprecated warnings due to older ICU versions. [refs #32](https://github.com/nojimage/twitter-text-php/issues/32)

If you are using RHEL/CentOS 6, installing PHP using [the remi repository](https://rpms.remirepo.net/) is the best choice.
If you use remi, you can use the new ICU.

## Features ##

### Autolink ##

 - Add links to all matching Twitter usernames (no account verification).
 - Add links to all user lists (of the form @username/list-name).
 - Add links to all valid hashtags.
 - Add links to all URLs.
 - Support for international character sets.

### Extractor ###

 - Extract mentioned Twitter usernames (from anywhere in the tweet).
 - Extract replied to Twitter usernames (from start of the tweet).
 - Extract all user lists (of the form @username/list-name).
 - Extract all valid hashtags.
 - Extract all URLs.
 - Support for international character sets.

### Hit Highlighter ###

 - Highlight text specifed by a range by surrounding with a tag.
 - Support for highlighting when tweet has already been autolinked.
 - Support for international character sets.

### Validation ###

 - Validate different twitter text elements.
 - Support for international character sets.

### Parser ###

- Parses a given tweet text with the weighted character count configuration.

## Length validation ##

twitter-text 3.0 updates the config file with `emojiParsingEnabled` config option.
When true, twitter-text-php will parse and discount emoji supported by the [Unicode Emoji 11.0](http://www.unicode.org/emoji/charts-11.0) (NOTE: Original [twitter-text](https://github.com/twitter/twitter-text) supported [twemoji library](https://github.com/twitter/twemoji)).
The length of these emoji will be the default weight (200 or two characters) even if they contain multiple code points combined by zero-width joiners.
This means that emoji with skin tone and gender modifiers no longer count as more characters than those without such modifiers.

twitter-text 2.0 introduced configuration files that define how Tweets are parsed for length. This allows for backwards compatibility and flexibility going forward.
Old-style traditional 140-character parsing is defined by the v1.json configuration file, whereas v2.json is updated for "weighted" Tweets where ranges of Unicode code points can have independent weights aside from the default weight.
The sum of all code points, each weighted appropriately, should not exceed the max weighted length.

Some old methods from twitter-text-php 1.0 have been marked deprecated, such as the `Twitter\Text\Validator::isValidTweetText()`, `Twitter\Text\Validator::getTweetLength()` method. The new API is based on the following method, `Twitter\Text\Parser::parseTweet()`

```(php)
use Twitter\Text\Parser;
$parser = new Parser();
$result = $parser->parseTweet($text);
```

This method takes a string as input and returns a results object that contains information about the string. `Twitter\Text\ParseResults` object includes:

- `weightedLength`: the overall length of the tweet with code points
weighted per the ranges defined in the configuration file.

- `permillage`: indicates the proportion (per thousand) of the weighted
length in comparison to the max weighted length. A value > 1000
indicates input text that is longer than the allowable maximum.

- `valid`: indicates if input text length corresponds to a valid
result.

- `displayRangeStart, displayRangeEnd`: An array of two unicode code point
indices identifying the inclusive start and exclusive end of the
displayable content of the Tweet. For more information, see
the description of `display_text_range` here:
[Tweet updates](https://developer.twitter.com/en/docs/tweets/tweet-updates)

- `validRangeStart, validRangeRnd`: An array of two unicode code point
indices identifying the inclusive start and exclusive end of the valid
content of the Tweet. For more information on the extended Tweet
payload see [Tweet updates](https://developer.twitter.com/en/docs/tweets/tweet-updates)

## Examples ##

For examples, please see `tests/example.php` which you can view in a browser or
run from the command line.

## Conformance ##

You'll need the test data which is in YAML format from the following
repository:

    https://github.com/twitter/twitter-text

`twitter/twitter-text` already included in `composer.json`, so you should just need to run:

    curl -s https://getcomposer.org/installer | php
    php composer.phar install

There are a couple of options for testing conformance:

- Run `phpunit` in from the root folder of the project.

## Thanks & Contributions ##

The bulk of this library is from the heroic efforts of:

 - Matt Sanford (https://github.com/mzsanford): For the orignal Ruby and Java implementions.
 - Mike Cochrane (https://github.com/mikenz): For the initial PHP code.
 - Nick Pope (https://github.com/ngnpope): For the bulk of the maintenance work to date.
 - Takashi Nojima (https://github.com/nojimage): For ongoing maintenance work.
