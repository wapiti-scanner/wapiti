<?php

class WPCF7_SWV_RequiredFileRule extends WPCF7_SWV_Rule {

	const rule_name = 'requiredfile';

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

		$input = isset( $_FILES[$field]['tmp_name'] )
			? $_FILES[$field]['tmp_name'] : '';

		$input = wpcf7_array_flatten( $input );
		$input = wpcf7_exclude_blank( $input );

		if ( empty( $input ) ) {
			return new WP_Error( 'wpcf7_invalid_requiredfile',
				$this->get_property( 'error' )
			);
		}

		return true;
	}

	public function to_array() {
		return array( 'rule' => self::rule_name ) + (array) $this->properties;
	}
}
