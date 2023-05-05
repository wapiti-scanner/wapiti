<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class UniqueValue.
 *
 * @since 1.7.5
 */
class UniqueValue extends SmartTag {
	/**
	 * Default length of the unique value to be generated.
	 *
	 * @since 1.7.5
	 *
	 * @var int
	 */
	const DEFAULT_LENGTH = 16;

	/**
	 * Default format of the unique value to be generated.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	const DEFAULT_FORMAT = 'alphanumeric';

	/**
	 * Get smart tag value.
	 *
	 * @since 1.7.5
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return string
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		$length     = self::DEFAULT_LENGTH;
		$format     = self::DEFAULT_FORMAT;
		$attributes = $this->get_attributes();

		if ( array_key_exists( 'length', $attributes ) ) {
			$length = max( $length, absint( $attributes['length'] ) );
		}

		if ( array_key_exists( 'format', $attributes ) && ! empty( $attributes['format'] ) ) {
			$format = $attributes['format'];
		}

		return $this->generate_string( $length, $format );
	}

	/**
	 * Generates a random string in defined format.
	 *
	 * @since 1.7.5
	 *
	 * @param int    $length Optional. The length of string to generate.
	 * @param string $format The format of string to generate. Accepts 'alphanumeric',
	 *                       'numeric', and 'alpha'. Default 'alphanumeric'.
	 *
	 * @return string
	 */
	private function generate_string( $length = 16, $format = 'alphanumeric' ) {

		$alpha   = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$numbers = '0123456789';

		switch ( strtolower( $format ) ) {
			case 'numeric':
				$chars = $numbers;
				break;

			case 'alpha':
				$chars = $alpha;
				break;

			default:
				$chars = $alpha . $numbers;
				break;
		}

		$chars = str_pad( $chars, $length, $chars );

		return substr( str_shuffle( $chars ), 0, $length );
	}
}
