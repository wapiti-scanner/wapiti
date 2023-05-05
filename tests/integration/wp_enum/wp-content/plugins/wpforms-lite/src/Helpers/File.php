<?php

namespace WPForms\Helpers;

/**
 * Class File.
 *
 * @since 1.6.5
 */
class File {

	/**
	 * Remove UTF-8 BOM signature if it presents.
	 *
	 * @since 1.6.5
	 *
	 * @param string $string String to process.
	 *
	 * @return string
	 */
	public static function remove_utf8_bom( $string ) {

		if ( strpos( bin2hex( $string ), 'efbbbf' ) === 0 ) {
			$string = substr( $string, 3 );
		}

		return $string;
	}
}
