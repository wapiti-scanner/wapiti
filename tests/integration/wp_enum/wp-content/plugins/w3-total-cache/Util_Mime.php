<?php
namespace W3TC;

class Util_Mime {
	/**
	 * Returns file mime type
	 *
	 * @param string  $file
	 * @return string
	 */
	static public function get_mime_type( $file ) {
		static $cache = array();

		if ( !isset( $cache[$file] ) ) {
			$mime_type = false;

			/**
			 * Try to detect by extension (fast)
			 */
			$mime_types = include W3TC_INC_DIR . '/mime/all.php';

			foreach ( $mime_types as $extension => $type ) {
				if ( preg_match( '~\.(' . $extension . ')$~i', $file ) ) {
					if ( is_array( $type ) )
						$mime_type = array_pop( $type );
					else
						$mime_type = $type;
					break;
				}
			}

			/**
			 * Try to detect using file info function
			 */
			if ( !$mime_type && function_exists( 'finfo_open' ) ) {
				$finfo = @finfo_open( FILEINFO_MIME );

				if ( !$finfo ) {
					$finfo = @finfo_open( FILEINFO_MIME );
				}

				if ( $finfo ) {
					$mime_type = @finfo_file( $finfo, $file );

					if ( $mime_type ) {
						$extra_mime_type_info = strpos( $mime_type, "; " );

						if ( $extra_mime_type_info ) {
							$mime_type = substr( $mime_type, 0, $extra_mime_type_info );
						}

						if ( $mime_type == 'application/octet-stream' ) {
							$mime_type = false;
						}
					}

					@finfo_close( $finfo );
				}
			}

			/**
			 * Try to detect using mime type function
			 */
			if ( !$mime_type && function_exists( 'mime_content_type' ) ) {
				$mime_type = @mime_content_type( $file );
			}

			/**
			 * If detection failed use default mime type
			 */
			if ( !$mime_type ) {
				$mime_type = 'application/octet-stream';
			}

			$cache[$file] = $mime_type;
		}

		return $cache[$file];
	}



	static public function sections_to_mime_types_map() {
		static $sections_to_mime_types_array = null;

		if ( is_null( $sections_to_mime_types_array ) ) {
			$sections_to_mime_types_array = array(
				'cssjs' => include W3TC_INC_DIR . '/mime/cssjs.php',
				'html' => include W3TC_INC_DIR . '/mime/html.php',
				'other' => include W3TC_INC_DIR . '/mime/other.php'
			);
		}

		return $sections_to_mime_types_array;
	}



	static public function mime_type_to_section( $mime_type ) {
		static $mime_type_to_section_array = null;

		if ( is_null( $mime_type_to_section_array ) ) {
			$sections = self::sections_to_mime_types_map();

			$mime_type_to_section_array = array();

			foreach ( $sections as $section => $mime_types ) {
				foreach ( $mime_types as $mime_type ) {
					$mime_type_to_section_array[$mime_type] = $section;
				}
			}
		}

		return isset( $mime_type_to_section_array[$mime_type] ) ?
			$mime_type_to_section_array[$mime_type] : null;
	}
}
