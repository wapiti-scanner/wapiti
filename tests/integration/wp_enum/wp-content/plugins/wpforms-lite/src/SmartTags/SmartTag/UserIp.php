<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class UserIp.
 *
 * @since 1.6.7
 */
class UserIp extends SmartTag {

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

		return esc_html( wpforms_get_ip() );
	}
}
