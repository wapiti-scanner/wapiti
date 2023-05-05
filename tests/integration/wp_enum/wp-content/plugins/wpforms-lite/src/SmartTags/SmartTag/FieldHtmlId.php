<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class FieldHtmlId.
 *
 * @since 1.6.7
 */
class FieldHtmlId extends SmartTag {

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

		if ( ! isset( $attributes['field_html_id'] ) || ! is_numeric( $attributes['field_html_id'] ) || $attributes['field_html_id'] < 0 ) {
			return '';
		}

		$field_id = absint( $attributes['field_html_id'] );

		if ( empty( $fields[ $field_id ] ) ) {
			return '';
		}

		$value = ! isset( $fields[ $field_id ]['value'] ) || (string) $fields[ $field_id ]['value'] === ''
			? '<em>' . esc_html__( '(empty)', 'wpforms-lite' ) . '</em>'
			: wp_kses_post( wp_unslash( $fields[ $field_id ]['value'] ) );

		/**
		 * Modify value for the {field_html_id="123"} tag.
		 *
		 * @since 1.4.0
		 *
		 * @param string $value     Smart tag value.
		 * @param array  $field     The field.
		 * @param array  $form_data Processed form settings/data, prepared to be used later.
		 * @param string $context   Context usage.
		 */
		return (string) apply_filters( 'wpforms_html_field_value', $value, $fields[ $field_id ], $form_data, 'smart-tag' );
	}
}
