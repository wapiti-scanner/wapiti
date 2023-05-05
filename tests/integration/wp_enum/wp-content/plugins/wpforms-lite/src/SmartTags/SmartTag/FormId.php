<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class FormId.
 *
 * @since 1.6.7
 */
class FormId extends SmartTag {

	/**
	 * Get smart tag value.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return int
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		return ! empty( $form_data['id'] ) ? absint( $form_data['id'] ) : 0;
	}
}
