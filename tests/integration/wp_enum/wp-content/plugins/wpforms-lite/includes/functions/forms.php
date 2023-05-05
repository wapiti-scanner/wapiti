<?php
/**
 * Helper functions to work with forms and form data.
 *
 * @since 1.8.0
 */

/**
 * Helper function to trigger displaying a form.
 *
 * @since 1.0.2
 *
 * @param mixed $form_id Form ID.
 * @param bool  $title   Form title.
 * @param bool  $desc    Form description.
 */
function wpforms_display( $form_id = false, $title = false, $desc = false ) {

	wpforms()->frontend->output( $form_id, $title, $desc );
}

/**
 * Return URL to form preview page.
 *
 * @since 1.5.1
 *
 * @param int  $form_id    Form ID.
 * @param bool $new_window New window flag.
 *
 * @return string
 */
function wpforms_get_form_preview_url( $form_id, $new_window = false ) {

	$url = add_query_arg(
		[
			'wpforms_form_preview' => absint( $form_id ),
		],
		home_url()
	);

	if ( $new_window ) {
		$url = add_query_arg(
			[
				'new_window' => 1,
			],
			$url
		);
	}

	return $url;
}

/**
 * Perform json_decode and unslash.
 *
 * IMPORTANT: This function decodes the result of wpforms_encode() properly only if
 * wp_insert_post() or wp_update_post() were used after the data is encoded.
 * Both wp_insert_post() and wp_update_post() remove excessive slashes added by wpforms_encode().
 *
 * Using wpforms_decode() on wpforms_encode() result directly
 * (without using wp_insert_post() or wp_update_post() first) always returns null or false.
 *
 * @since 1.0.0
 *
 * @param string $data Data to decode.
 *
 * @return array|false|null
 */
function wpforms_decode( $data ) {

	if ( ! $data || empty( $data ) ) {
		return false;
	}

	return wp_unslash( json_decode( $data, true ) );
}

/**
 * Perform json_encode and wp_slash.
 *
 * IMPORTANT: This function adds excessive slashes to prevent data damage
 * by wp_insert_post() or wp_update_post() that use wp_unslash() on all the incoming data.
 *
 * Decoding the result of this function by wpforms_decode() directly
 * (without using wp_insert_post() or wp_update_post() first) always returns null or false.
 *
 * @since 1.3.1.3
 *
 * @param mixed $data Data to encode.
 *
 * @return string|false
 */
function wpforms_encode( $data = false ) {

	if ( empty( $data ) ) {
		return false;
	}

	return wp_slash( wp_json_encode( $data ) );
}

/**
 * Decode json-encoded string if it is in json format.
 *
 * @since 1.7.5
 *
 * @param string $string      A string.
 * @param bool   $associative Decode to the associative array if true. Decode to object if false.
 *
 * @return array|string
 */
function wpforms_json_decode( $string, $associative = false ) {

	$string = html_entity_decode( $string );

	if ( ! wpforms_is_json( $string ) ) {
		return $string;
	}

	return json_decode( $string, $associative );
}

/**
 * Get the value of a specific WPForms setting.
 *
 * @since 1.0.0
 *
 * @param string $key     Setting name.
 * @param mixed  $default Default value to return if the setting is not available.
 * @param string $option  Option key, defaults to `wpforms_settings` in the `wp_options` table.
 *
 * @return mixed
 */
function wpforms_setting( $key, $default = false, $option = 'wpforms_settings' ) {

	$key     = wpforms_sanitize_key( $key );
	$options = get_option( $option, false );
	$value   = is_array( $options ) && ! empty( $options[ $key ] ) ? wp_unslash( $options[ $key ] ) : $default;

	/**
	 * Allows plugin setting to be modified.
	 *
	 * @since 1.7.8
	 *
	 * @param mixed  $value   Setting value.
	 * @param string $key     Setting key.
	 * @param mixed  $default Setting default value.
	 * @param string $option  Settings option name.
	 */
	$value = apply_filters( 'wpforms_setting', $value, $key, $default, $option );

	return $value;
}

/**
 * Update plugin settings option and allow it to be filterable.
 *
 * @since 1.6.6
 *
 * @param array $settings A plugin settings array that is saved into options table.
 *
 * @return bool
 */
function wpforms_update_settings( $settings ) {

	/**
	 * Allows plugin settings to be modified before persisting in the database.
	 *
	 * @since 1.6.6
	 *
	 * @param array $settings An array of plugin settings to modify.
	 */
	$settings = (array) apply_filters( 'wpforms_update_settings', $settings );

	$updated = update_option( 'wpforms_settings', $settings );

	/**
	 * Fires after the plugin settings were persisted in the database.
	 *
	 * The `$updated` parameter allows to check whether the update was actually successful.
	 *
	 * @since 1.6.1
	 *
	 * @param array  $settings An array of plugin settings.
	 * @param bool   $updated  Whether an option was updated or not.
	 */
	do_action( 'wpforms_settings_updated', $settings, $updated );

	return $updated;
}

/**
 * Check if form provided contains the specified field type.
 *
 * @since 1.0.5
 *
 * @param array|string $type     Field type or types.
 * @param array|object $form     Form data object.
 * @param bool         $multiple Whether to check multiple field types.
 *
 * @return bool
 */
function wpforms_has_field_type( $type, $form, $multiple = false ) {

	$form_data = '';
	$field     = false;
	$type      = (array) $type;

	if ( $multiple ) {
		foreach ( $form as $single_form ) {
			$field = wpforms_has_field_type( $type, $single_form );

			if ( $field ) {
				break;
			}
		}

		return $field;
	}

	if ( is_object( $form ) && ! empty( $form->post_content ) ) {
		$form_data = wpforms_decode( $form->post_content );
	} elseif ( is_array( $form ) ) {
		$form_data = $form;
	}

	if ( empty( $form_data['fields'] ) ) {
		return false;
	}

	foreach ( $form_data['fields'] as $single_field ) {
		if ( ! empty( $single_field['type'] ) && in_array( $single_field['type'], $type, true ) ) {
			$field = true;

			break;
		}
	}

	return $field;
}

/**
 * Check if form provided contains a field which a specific setting.
 *
 * @since 1.4.5
 *
 * @param string       $setting  Setting key.
 * @param object|array $form     Form data.
 * @param bool         $multiple Whether to check multiple settings.
 *
 * @return bool
 */
function wpforms_has_field_setting( $setting, $form, $multiple = false ) {

	$form_data = '';
	$field     = false;

	if ( $multiple ) {
		foreach ( $form as $single_form ) {
			$field = wpforms_has_field_setting( $setting, $single_form );

			if ( $field ) {
				break;
			}
		}

		return $field;
	}

	if ( is_object( $form ) && ! empty( $form->post_content ) ) {
		$form_data = wpforms_decode( $form->post_content );
	} elseif ( is_array( $form ) ) {
		$form_data = $form;
	}

	if ( empty( $form_data['fields'] ) ) {
		return false;
	}

	foreach ( $form_data['fields'] as $single_field ) {

		if ( ! empty( $single_field[ $setting ] ) ) {
			$field = true;

			break;
		}
	}

	return $field;
}

/**
 * Retrieve actual fields from a form.
 *
 * Non-posting elements such as section divider, page break, and HTML are
 * automatically excluded. Optionally a white list can be provided.
 *
 * @since 1.0.0
 *
 * @param mixed $form      Form data.
 * @param array $allowlist A list of allowed fields.
 *
 * @return mixed boolean or array
 */
function wpforms_get_form_fields( $form = false, $allowlist = [] ) {

	// Accept form (post) object or form ID.
	if ( is_object( $form ) ) {
		$form = wpforms_decode( $form->post_content );
	} elseif ( is_numeric( $form ) ) {
		$form = wpforms()->get( 'form' )->get(
			$form,
			[
				'content_only' => true,
			]
		);
	}

	// White list of field types to allow.
	$allowed_form_fields = [
		'address',
		'checkbox',
		'date-time',
		'email',
		'file-upload',
		'gdpr-checkbox',
		'hidden',
		'likert_scale',
		'name',
		'net_promoter_score',
		'number',
		'number-slider',
		'payment-checkbox',
		'payment-multiple',
		'payment-select',
		'payment-single',
		'payment-total',
		'phone',
		'radio',
		'rating',
		'richtext',
		'select',
		'signature',
		'text',
		'textarea',
		'url',
	];

	$allowed_form_fields = apply_filters( 'wpforms_get_form_fields_allowed', $allowed_form_fields );

	if ( ! is_array( $form ) || empty( $form['fields'] ) ) {
		return false;
	}

	$allowlist = ! empty( $allowlist ) ? $allowlist : $allowed_form_fields;

	$form_fields = $form['fields'];

	foreach ( $form_fields as $id => $form_field ) {
		if ( ! in_array( $form_field['type'], $allowlist, true ) ) {
			unset( $form_fields[ $id ] );
		}
	}

	return $form_fields;
}

/**
 * Conditional logic form fields supported.
 *
 * @since 1.5.2
 *
 * @return array
 */
function wpforms_get_conditional_logic_form_fields_supported() {

	$fields_supported = [
		'checkbox',
		'email',
		'hidden',
		'net_promoter_score',
		'number',
		'number-slider',
		'payment-checkbox',
		'payment-multiple',
		'payment-select',
		'radio',
		'rating',
		'richtext',
		'select',
		'text',
		'textarea',
		'url',
	];

	return apply_filters( 'wpforms_get_conditional_logic_form_fields_supported', $fields_supported );
}

/**
 * Get meta key value for a form field.
 *
 * @since 1.3.1
 * @since 1.5.0 More strict parameters. Always return an array.
 *
 * @param string $key       Meta key.
 * @param string $value     Meta value to check against.
 * @param array  $form_data Form data array.
 *
 * @return array Empty array, when no data is found.
 */
function wpforms_get_form_fields_by_meta( $key, $value, $form_data ) {

	$found = [];

	if ( empty( $key ) || empty( $value ) || empty( $form_data['fields'] ) ) {
		return $found;
	}

	foreach ( $form_data['fields'] as $id => $field ) {

		if ( ! empty( $field['meta'][ $key ] ) && $value === $field['meta'][ $key ] ) {
			$found[ $id ] = $field;
		}
	}

	return $found;
}

/**
 * Retrieve the full config for CAPTCHA.
 *
 * @since 1.6.4
 *
 * @return array
 */
function wpforms_get_captcha_settings() {

	$allowed_captcha_list = [ 'hcaptcha', 'recaptcha', 'turnstile' ];
	$captcha_provider     = wpforms_setting( 'captcha-provider', 'recaptcha' );

	if ( ! in_array( $captcha_provider, $allowed_captcha_list, true ) ) {
		return [
			'provider' => 'none',
		];
	}

	return [
		'provider'       => $captcha_provider,
		'site_key'       => sanitize_text_field( wpforms_setting( "{$captcha_provider}-site-key", '' ) ),
		'secret_key'     => sanitize_text_field( wpforms_setting( "{$captcha_provider}-secret-key", '' ) ),
		'recaptcha_type' => wpforms_setting( 'recaptcha-type', 'v2' ),
		'theme'          => sanitize_text_field( wpforms_setting( "{$captcha_provider}-theme", '' ) ),
	];
}

/**
 * Process smart tags.
 *
 * @since 1.7.1
 *
 * @param string $content   Content.
 * @param array  $form_data Form data.
 * @param array  $fields    List of fields.
 * @param string $entry_id  Entry ID.
 *
 * @return string
 */
function wpforms_process_smart_tags( $content, $form_data, $fields = [], $entry_id = '' ) {

	// Skip it if variables have invalid format.
	if ( ! is_string( $content ) || ! is_array( $form_data ) || ! is_array( $fields ) ) {
		return $content;
	}

	/**
	 * Process smart tags.
	 *
	 * @since 1.4.0
	 *
	 * @param string $content   Content.
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return string
	 */
	return apply_filters( 'wpforms_process_smart_tags',  $content, $form_data, $fields, $entry_id );
}
