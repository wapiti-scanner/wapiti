<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class Date.
 *
 * @since 1.6.7
 */
class Date extends SmartTag {

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
		$format     = ! empty( $attributes['format'] ) ? $attributes['format'] : get_option( 'date_format' );

		return wpforms_datetime_format( time(), $format, true );
	}
}
