<?php

namespace WPForms\Helpers;

/**
 * Chain monad, useful for chaining certain array or string related functions.
 *
 * @since 1.5.6
 *
 * @method Chain array_change_key_case()
 * @method Chain array_chunk()
 * @method Chain array_column()
 * @method Chain array_combine()
 * @method Chain array_count_values()
 * @method Chain array_diff_assoc()
 * @method Chain array_diff_key()
 * @method Chain array_diff_uassoc()
 * @method Chain array_diff_ukey()
 * @method Chain array_diff(array $var)
 * @method Chain array_fill_keys()
 * @method Chain array_fill()
 * @method Chain array_filter()
 * @method Chain array_flip()
 * @method Chain array_intersect_assoc()
 * @method Chain array_intersect_key()
 * @method Chain array_intersect_uassoc()
 * @method Chain array_intersect_ukey()
 * @method Chain array_intersect(array $var)
 * @method Chain array_key_first()
 * @method Chain array_key_last()
 * @method Chain array_keys()
 * @method Chain array_map()
 * @method Chain array_merge_recursive()
 * @method Chain array_merge(array $var)
 * @method Chain array_pad()
 * @method Chain array_pop()
 * @method Chain array_product()
 * @method Chain array_rand()
 * @method Chain array_reduce()
 * @method Chain array_replace_recursive()
 * @method Chain array_replace()
 * @method Chain array_reverse()
 * @method Chain array_shift()
 * @method Chain array_slice()
 * @method Chain array_splice()
 * @method Chain array_sum()
 * @method Chain array_udiff_assoc()
 * @method Chain array_udiff_uassoc()
 * @method Chain array_udiff()
 * @method Chain array_uintersect_assoc()
 * @method Chain array_uintersect_uassoc()
 * @method Chain array_uintersect()
 * @method Chain array_unique()
 * @method Chain array_values()
 * @method Chain count()
 * @method Chain current()
 * @method Chain end()
 * @method Chain key()
 * @method Chain next()
 * @method Chain prev()
 * @method Chain range()
 * @method Chain reset()
 * @method Chain ltrim()
 * @method Chain rtrim()
 * @method Chain md5()
 * @method Chain str_getcsv()
 * @method Chain str_ireplace()
 * @method Chain str_pad()
 * @method Chain str_repeat()
 * @method Chain str_rot13()
 * @method Chain str_shuffle()
 * @method Chain str_split()
 * @method Chain str_word_count()
 * @method Chain strcasecmp()
 * @method Chain strchr()
 * @method Chain strcmp()
 * @method Chain strcoll()
 * @method Chain strcspn()
 * @method Chain strip_tags()
 * @method Chain stripcslashes()
 * @method Chain stripos()
 * @method Chain stripslashes()
 * @method Chain stristr()
 * @method Chain strlen()
 * @method Chain strnatcasecmp()
 * @method Chain strnatcmp()
 * @method Chain strncasecmp()
 * @method Chain strncmp()
 * @method Chain strpbrk()
 * @method Chain strpos()
 * @method Chain strrchr()
 * @method Chain strrev()
 * @method Chain strripos()
 * @method Chain strrpos()
 * @method Chain strspn()
 * @method Chain strstr()
 * @method Chain strtok()
 * @method Chain strtolower()
 * @method Chain strtoupper()
 * @method Chain strtr()
 * @method Chain substr_compare()
 * @method Chain substr_count()
 * @method Chain substr_replace()
 * @method Chain substr()
 * @method Chain trim()
 * @method Chain ucfirst()
 * @method Chain ucwords()
 * @method Chain vfprintf()
 * @method Chain vprintf()
 * @method Chain vsprintf()
 * @method Chain wordwrap()
 */
class Chain {

	/**
	 * Current value.
	 *
	 * @since 1.5.6
	 *
	 * @var mixed
	 */
	private $value;

	/**
	 * Class constructor.
	 *
	 * @since 1.5.6
	 *
	 * @param mixed $value Current value to start working with.
	 */
	public function __construct( $value ) {

		$this->value = $value;
	}

	/**
	 * Bind some function to value.
	 *
	 * @since 1.5.6
	 *
	 * @param mixed $fn Some function.
	 *
	 * @return Chain
	 */
	public function bind( $fn ) {

		$this->value = $fn( $this->value );

		return $this;
	}

	/**
	 * Get value.
	 *
	 * @since 1.5.6
	 *
	 * @return mixed
	 */
	public function value() {

		return $this->value;
	}

	/**
	 * Magic call.
	 *
	 * @since 1.5.6
	 *
	 * @param string $name Method name.
	 * @param array  $params Parameters.
	 *
	 * @throws \BadFunctionCallException Invalid function is called.
	 *
	 * @return Chain
	 */
	public function __call( $name, $params ) {

		if ( in_array( $name, $this->allowed_methods(), true ) ) {

			$params = $params === null ? [] : $params;

			array_unshift( $params, $this->value );

			$this->value = call_user_func_array( $name, array_values( $params ) );

			return $this;
		}

		throw new \BadFunctionCallException( "Provided function { $name } is not allowed. See Chain::allowed_methods()." );
	}

	/**
	 * Join array elements with a string.
	 *
	 * @since 1.5.6
	 *
	 * @param string $glue Defaults to an empty string.
	 *
	 * @return Chain
	 */
	public function implode( $glue = '' ) {

		$this->value = implode( $glue, $this->value );

		return $this;
	}

	/**
	 * Split a string by a string.
	 *
	 * @since 1.5.6
	 *
	 * @param string $delimiter The boundary string.
	 *
	 * @return Chain
	 */
	public function explode( $delimiter ) {

		$this->value = explode( $delimiter, $this->value );

		return $this;
	}

	/**
	 * Apply the callback to the elements of the given arrays.
	 *
	 * @since 1.5.6
	 *
	 * @param callable $cb Callback.
	 *
	 * @return Chain
	 */
	public function map( $cb ) {

		$this->value = array_map( $cb, $this->value );

		return $this;
	}

	/**
	 * Pop array.
	 *
	 * @since 1.5.6
	 *
	 * @return Chain
	 */
	public function pop() {

		$this->value = array_pop( $this->value );

		return $this;
	}

	/**
	 * Run first or second callback based on a condition.
	 *
	 * @since 1.5.6
	 *
	 * @param callable $condition Condition function.
	 * @param callable $true_result If condition will return true we run this function.
	 * @param callable $false_result If condition will return false we run this function.
	 *
	 * @return Chain
	 */
	public function iif( $condition, $true_result, $false_result = null ) {

		if ( ! is_callable( $false_result ) ) {
			$false_result = function() {
				return '';
			};
		}
		$this->value = array_map(
			function( $el ) use ( $condition, $true_result, $false_result ) {
				if ( call_user_func( $condition, $el ) ) {
					return call_user_func( $true_result, $el );
				}
				return call_user_func( $false_result, $el );
			},
			$this->value
		);

		return $this;
	}

	/**
	 * All allowed methods to work with data.
	 *
	 * @since 1.5.6
	 *
	 * @return array
	 */
	public function allowed_methods() {

		return [
			'array_change_key_case',
			'array_chunk',
			'array_column',
			'array_combine',
			'array_count_values',
			'array_diff_assoc',
			'array_diff_key',
			'array_diff_uassoc',
			'array_diff_ukey',
			'array_diff',
			'array_fill_keys',
			'array_fill',
			'array_filter',
			'array_flip',
			'array_intersect_assoc',
			'array_intersect_key',
			'array_intersect_uassoc',
			'array_intersect_ukey',
			'array_intersect',
			'array_key_first',
			'array_key_last',
			'array_keys',
			'array_map',
			'array_merge_recursive',
			'array_merge',
			'array_pad',
			'array_pop',
			'array_product',
			'array_rand',
			'array_reduce',
			'array_replace_recursive',
			'array_replace',
			'array_reverse',
			'array_shift',
			'array_slice',
			'array_splice',
			'array_sum',
			'array_udiff_assoc',
			'array_udiff_uassoc',
			'array_udiff',
			'array_uintersect_assoc',
			'array_uintersect_uassoc',
			'array_uintersect',
			'array_unique',
			'array_values',
			'count',
			'current',
			'end',
			'key',
			'next',
			'prev',
			'range',
			'reset',
			'implode',
			'ltrim',
			'rtrim',
			'md5',
			'str_getcsv',
			'str_ireplace',
			'str_pad',
			'str_repeat',
			'str_rot13',
			'str_shuffle',
			'str_split',
			'str_word_count',
			'strcasecmp',
			'strchr',
			'strcmp',
			'strcoll',
			'strcspn',
			'strip_tags',
			'stripcslashes',
			'stripos',
			'stripslashes',
			'stristr',
			'strlen',
			'strnatcasecmp',
			'strnatcmp',
			'strncasecmp',
			'strncmp',
			'strpbrk',
			'strpos',
			'strrchr',
			'strrev',
			'strripos',
			'strrpos',
			'strspn',
			'strstr',
			'strtok',
			'strtolower',
			'strtoupper',
			'strtr',
			'substr_compare',
			'substr_count',
			'substr_replace',
			'substr',
			'trim',
			'ucfirst',
			'ucwords',
			'vfprintf',
			'vprintf',
			'vsprintf',
			'wordwrap',
		];
	}

	/**
	 * Create myself.
	 *
	 * @since 1.5.6
	 *
	 * @param mixed $value Current.
	 *
	 * @return Chain
	 */
	public static function of( $value = null ) {

		return new self( $value );
	}
}
