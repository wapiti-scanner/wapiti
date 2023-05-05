<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class Generic.
 *
 * @since 1.6.7.1
 */
class Generic extends SmartTag {

	/**
	 * Mock for the get_value method.
	 *
	 * @since 1.6.7.1
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return null
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		return null;
	}
}
