# Changes

## 3.1.2

- Hit highlighting: avoid errors with PHP 8.

## 3.0.0

- Pass twitter-text conformance 3.0.0
- Change default configuration to v3 (emojiParsingEnabled=true)
- Add t.co with query string support
- Add Directional Characters support

## 2.0.2

- Pass twitter-text conformance 2.0.5
- Change default configuration to v2 in `Validator`.

## 2.0.1

- Fixes wrong method call in Extractor::extract() #19

## 2.0.0

- Pass twitter-text conformance 2.0.0
- Add to required php extension, `mbstring` and `intl`.
- Add `Parser`, `ParseResults`, `Configuration` class for twitter-text 2.0 "weighted" tweets.
- Twtter\Text classes no longer extended Regex class.
- Deprecated `Validator::isValidTweetText()`, `Validator::getTweetLength()`.
- `Extractor` constractor no longer accepts `$tweet`
- `Validator` constractor no longer accepts `$tweet` and `$config`. `Validator` constractor only accepts `Configuration` incetance.
