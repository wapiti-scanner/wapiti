<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class FieldId.
 *
 * @since 1.6.7
 */
class FieldId extends SmartTag {

	/**
	 * Get smart tag value.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return string
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		$attributes = $this->get_attributes();

		if ( ! isset( $attributes['field_id'] ) || $attributes['field_id'] === '' ) {
			return '';
		}

		$field_parts = explode( '|', $attributes['field_id'] );
		$field_id    = $field_parts[0];

		if ( ! isset( $fields[ $field_id ] ) || $fields[ $field_id ] === '' ) {
			return '';
		}

		$field_key = ! empty( $field_parts[1] ) ? sanitize_key( $field_parts[1] ) : 'value';
		$value     = isset( $fields[ $field_id ][ $field_key ] ) ? wp_kses_post( wp_unslash( $fields[ $field_id ][ $field_key ] ) ) : '';

		/**
		 * Modify value for the `field_id` smart tag.
		 *
		 * @since      1.5.3
		 * @deprecated 1.6.7
		 *
		 * @see This filter is documented in wp-includes/plugin.php
		 *
		 * @param string Smart tag value.
		 */
		return (string) apply_filters_deprecated(
			'wpforms_field_smart_tag_value',
			[ $value ],
			'1.6.7',
			'wpforms_smarttags_process_field_id_value'
		);
	}
}
