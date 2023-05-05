<?php
/**
 * Rule compiler for Jetpack Waf.
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

/**
 * Waf_Operators class
 */
class Waf_Operators {
	/**
	 * Returns true if the test string is found at the beginning of the input.
	 *
	 * @param string $input Input.
	 * @param string $test Test.
	 * @return string|false
	 */
	public function begins_with( $input, $test ) {
		if ( '' === $input && '' === $test ) {
			return '';
		}

		return substr( $input, 0, strlen( $test ) ) === $test
		? $test
		: false;
	}

	/**
	 * Returns true if the test string is found anywhere in the input.
	 *
	 * @param string $input Input.
	 * @param string $test Test.
	 * @return string|false
	 */
	public function contains( $input, $test ) {
		if ( empty( $input ) || empty( $test ) ) {
			return false;
		}

		return strpos( $input, $test ) !== false
		? $test
		: false;
	}

	/**
	 * Returns true if the test string with word boundaries is found anywhere in the input.
	 *
	 * @param string $input Input.
	 * @param string $test Test.
	 * @return string|false
	 */
	public function contains_word( $input, $test ) {
		return ( $input === $test || 1 === preg_match( '/\b' . preg_quote( $test, '/' ) . '\b/Ds', $input ) )
		? $test
		: false;
	}

	/**
	 * Returns true if the test string is found at the end of the input.
	 *
	 * @param string $input Input.
	 * @param string $test Test.
	 * @return string|false
	 */
	public function ends_with( $input, $test ) {
		return ( '' === $test || substr( $input, -1 * strlen( $test ) ) === $test )
		? $test
		: false;
	}

	/**
	 * Returns true if the input value is equal to the test value.
	 * If either value cannot be converted to an int it will be treated as 0.
	 *
	 * @param mixed $input Input.
	 * @param mixed $test Test.
	 * @return int|false
	 */
	public function eq( $input, $test ) {
		return intval( $input ) === intval( $test )
		? $input
		: false;
	}

	/**
	 * Returns true if the input value is greater than or equal to the test value.
	 * If either value cannot be converted to an int it will be treated as 0.
	 *
	 * @param mixed $input Input.
	 * @param mixed $test Test.
	 * @return int|false
	 */
	public function ge( $input, $test ) {
		return intval( $input ) >= intval( $test )
		? $input
		: false;
	}

	/**
	 * Returns true if the input value is greater than the test value.
	 * If either value cannot be converted to an int it will be treated as 0.
	 *
	 * @param mixed $input Input.
	 * @param mixed $test Test.
	 * @return int|false
	 */
	public function gt( $input, $test ) {
		return intval( $input ) > intval( $test )
		? $input
		: false;
	}

	/**
	 * Returns true if the input value is less than or equal to the test value.
	 * If either value cannot be converted to an int it will be treated as 0.
	 *
	 * @param mixed $input Input.
	 * @param mixed $test Test.
	 * @return int|false
	 */
	public function le( $input, $test ) {
		return intval( $input ) <= intval( $test )
		? $input
		: false;
	}

	/**
	 * Returns true if the input value is less than the test value.
	 * If either value cannot be converted to an int it will be treated as 0.
	 *
	 * @param mixed $input Input.
	 * @param mixed $test Test.
	 * @return int|false
	 */
	public function lt( $input, $test ) {
		return intval( $input ) < intval( $test )
		? $input
		: false;
	}

	/**
	 * Returns false.
	 *
	 * @return false
	 */
	public function no_match() {
		return false;
	}

	/**
	 * Uses a multi-string matching algorithm to search through $input for a number of given $words.
	 *
	 * @param string   $input Input.
	 * @param string[] $words \AhoCorasick\MultiStringMatcher $matcher.
	 * @return string[]|false Returns the words that were found in $input, or FALSE if no words were found.
	 */
	public function pm( $input, $words ) {
		$results = $this->get_multi_string_matcher( $words )->searchIn( $input );

		return isset( $results[0] )
		? array_map(
			function ( $r ) {
				return $r[1]; },
			$results
		)
		: false;
	}

	/**
	 * The last-used pattern-matching algorithm.
	 *
	 * @var array
	 */
	private $last_multi_string_matcher = array( null, null );

	/**
	 * Creates a matcher that uses the Aho-Corasick algorithm to efficiently find a number of words in an input string.
	 * Caches the last-used matcher so that the same word list doesn't have to be compiled multiple times.
	 *
	 * @param string[] $words Words.
	 * @return \AhoCorasick\MultiStringMatcher
	 */
	private function get_multi_string_matcher( $words ) {
		// only create a new matcher entity if we don't have one already for this word list.
		if ( $this->last_multi_string_matcher[0] !== $words ) {
			$this->last_multi_string_matcher = array( $words, new \AhoCorasick\MultiStringMatcher( $words ) );
		}

		return $this->last_multi_string_matcher[1];
	}

	/**
	 * Performs a regular expression match on the input subject using the given pattern.
	 * Returns false if the pattern does not match, or the substring(s) of the input
	 * that were matched by the pattern.
	 *
	 * @param string $subject Subject.
	 * @param string $pattern Pattern.
	 * @return string[]|false
	 */
	public function rx( $subject, $pattern ) {
		$matched = preg_match( $pattern, $subject, $matches );
		return 1 === $matched
			? $matches
			: false;
	}

	/**
	 * Returns true if the given input string matches the test string.
	 *
	 * @param string $input Input.
	 * @param string $test Test.
	 * @return string|false
	 */
	public function streq( $input, $test ) {
		return $input === $test
		? $test
		: false;
	}

	/**
	 * Returns true.
	 *
	 * @param string $input Input.
	 * @return bool
	 */
	public function unconditional_match( $input ) {
		return $input;
	}

	/**
	 * Checks to see if the input string only contains characters within the given byte range
	 *
	 * @param string $input Input.
	 * @param array  $valid_range Valid range.
	 * @return string
	 */
	public function validate_byte_range( $input, $valid_range ) {
		if ( '' === $input ) {
			// an empty string is considered "valid".
			return false;
		}
		$i = 0;
		while ( isset( $input[ $i ] ) ) {
			$n = ord( $input[ $i ] );
			if ( $n < $valid_range['min'] || $n > $valid_range['max'] ) {
				return $input[ $i ];
			}
			$valid = false;
			foreach ( $valid_range['range'] as $b ) {
				if ( $n === $b || is_array( $b ) && $n >= $b[0] && $n <= $b[1] ) {
					$valid = true;
					break;
				}
			}
			if ( ! $valid ) {
				return $input[ $i ];
			}
			++$i;
		}

		// if there weren't any invalid bytes, return false.
		return false;
	}

	/**
	 * Returns true if the input value is found anywhere inside the test value
	 * (i.e. the inverse of @contains)
	 *
	 * @param mixed $input Input.
	 * @param mixed $test Test.
	 * @return string|false
	 */
	public function within( $input, $test ) {
		if ( '' === $input || '' === $test ) {
			return false;
		}

		return stripos( $test, $input ) !== false
		? $input
		: false;
	}
}
