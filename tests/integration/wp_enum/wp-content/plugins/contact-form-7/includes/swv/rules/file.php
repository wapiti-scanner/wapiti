<?php

class WPCF7_SWV_FileRule extends WPCF7_SWV_Rule {

	const rule_name = 'file';

	public function matches( $context ) {
		if ( false === parent::matches( $context ) ) {
			return false;
		}

		if ( empty( $context['file'] ) ) {
			return false;
		}

		return true;
	}

	public function validate( $context ) {
		$field = $this->get_property( 'field' );
		$input = isset( $_FILES[$field]['name'] ) ? $_FILES[$field]['name'] : '';
		$input = wpcf7_array_flatten( $input );
		$input = wpcf7_exclude_blank( $input );

		$acceptable_filetypes = array();

		foreach ( (array) $this->get_property( 'accept' ) as $accept ) {
			if ( false === strpos( $accept, '/' ) ) {
				$acceptable_filetypes[] = strtolower( $accept );
			} else {
				foreach ( wpcf7_convert_mime_to_ext( $accept ) as $ext ) {
					$acceptable_filetypes[] = sprintf(
						'.%s',
						strtolower( trim( $ext, ' .' ) )
					);
				}
			}
		}

		$acceptable_filetypes = array_unique( $acceptable_filetypes );

		foreach ( $input as $i ) {
			$last_period_pos = strrpos( $i, '.' );

			if ( false === $last_period_pos ) { // no period
				return new WP_Error( 'wpcf7_invalid_file',
					$this->get_property( 'error' )
				);
			}

			$suffix = strtolower( substr( $i, $last_period_pos ) );

			if ( ! in_array( $suffix, $acceptable_filetypes, true ) ) {
				return new WP_Error( 'wpcf7_invalid_file',
					$this->get_property( 'error' )
				);
			}
		}

		return true;
	}

	public function to_array() {
		return array( 'rule' => self::rule_name ) + (array) $this->properties;
	}
}
