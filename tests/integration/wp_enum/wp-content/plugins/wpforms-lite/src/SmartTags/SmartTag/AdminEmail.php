<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class AdminEmail.
 *
 * @since 1.6.7
 */
class AdminEmail extends SmartTag {

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

		return sanitize_email( get_option( 'admin_email' ) );
	}
}
