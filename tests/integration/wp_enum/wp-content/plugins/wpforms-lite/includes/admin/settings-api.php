<?php
/**
 * Settings API.
 *
 * @since 1.3.7
 */

/**
 * Settings output wrapper.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_output_field( $args ) {

	// Define default callback for this field type.
	$callback = ! empty( $args['type'] ) && function_exists( 'wpforms_settings_' . $args['type'] . '_callback' ) ? 'wpforms_settings_' . $args['type'] . '_callback' : 'wpforms_settings_missing_callback';

	// Allow custom callback to be provided via arg.
	if ( ! empty( $args['callback'] ) && function_exists( $args['callback'] ) ) {
		$callback = $args['callback'];
	}

	// Store returned markup from callback.
	$field = call_user_func( $callback, $args );

	// Allow arg to bypass standard field wrap for custom display.
	if ( ! empty( $args['wrap'] ) ) {
		return $field;
	}

	// Custom row classes.
	$class = ! empty( $args['class'] ) ? wpforms_sanitize_classes( (array) $args['class'], true ) : '';

	// Allow hiding blocks on page load (useful for JS toggles).
	$display_none = ! empty( $args['is_hidden'] ) ? 'style="display:none;"' : '';

	// Build standard field markup and return.
	$output = '<div class="wpforms-setting-row wpforms-setting-row-' . sanitize_html_class( $args['type'] ) . ' wpforms-clear ' . $class . '" id="wpforms-setting-row-' . wpforms_sanitize_key( $args['id'] ) . '" ' . $display_none . '>';

	if ( ! empty( $args['name'] ) && empty( $args['no_label'] ) ) {
		$output .= '<span class="wpforms-setting-label">';
		$output .= '<label for="wpforms-setting-' . wpforms_sanitize_key( $args['id'] ) . '">' . esc_html( $args['name'] ) . '</label>';
		$output .= '</span>';
	}

	$output .= '<span class="wpforms-setting-field">';
	$output .= $field;
	if ( ! empty( $args['desc_after'] ) ) {
		$output .= '<div class="wpforms-clear">' . $args['desc_after'] . '</div>';
	}
	$output .= '</span>';

	$output .= '</div>';

	return $output;
}

/**
 * Missing Callback.
 *
 * If a function is missing for settings callbacks alert the user.
 *
 * @since 1.3.9
 *
 * @param array $args Arguments passed by the setting.
 *
 * @return string
 */
function wpforms_settings_missing_callback( $args ) {

	return sprintf(
		/* translators: %s - ID of a setting. */
		esc_html__( 'The callback function used for the %s setting is missing.', 'wpforms-lite' ),
		'<strong>' . wpforms_sanitize_key( $args['id'] ) . '</strong>'
	);
}

/**
 * Settings content field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_content_callback( $args ) {
	return ! empty( $args['content'] ) ? $args['content'] : '';
}

/**
 * Settings license field callback.
 *
 * @since 1.3.9
 *
 * @param array $args Settings arguments.
 *
 * @return string
 */
function wpforms_settings_license_callback( $args ) {

	$output  = '<p>' . esc_html__( 'You\'re using WPForms Lite - no license needed. Enjoy!', 'wpforms-lite' ) . ' 🙂</p>';
	$output .=
		'<p>' .
		sprintf(
			wp_kses( /* translators: %s - WPForms.com upgrade URL. */
				__( 'To unlock more features consider <strong><a href="%s" target="_blank" rel="noopener noreferrer" class="wpforms-upgrade-modal">upgrading to PRO</a></strong>.', 'wpforms-lite' ),
				[
					'a'      => [
						'href'   => [],
						'class'  => [],
						'target' => [],
						'rel'    => [],
					],
					'strong' => [],
				]
			),
			esc_url( wpforms_admin_upgrade_link( 'settings-license', 'Upgrade to WPForms Pro text Link' ) )
		) .
		'</p>';
	$output .=
		'<p class="discount-note">' .
			wp_kses(
				__( 'As a valued WPForms Lite user you receive <strong>50% off</strong>, automatically applied at checkout!', 'wpforms-lite' ),
				[
					'strong' => [],
				]
			) .
		'</p>';

	$output .= '<hr><p>' . esc_html__( 'Already purchased? Simply enter your license key below to enable WPForms PRO!', 'wpforms-lite' ) . '</p>';
	$output .= '<p>';
	$output .= '<input type="password" spellcheck="false" id="wpforms-settings-upgrade-license-key" placeholder="' . esc_attr__( 'Paste license key here', 'wpforms-lite' ) . '" value="">';
	$output .= '<button type="button" class="wpforms-btn wpforms-btn-md wpforms-btn-orange" id="wpforms-settings-connect-btn">' . esc_html__( 'Verify Key', 'wpforms-lite' ) . '</button>';
	$output .= '</p>';

	/**
	 * Filter license settings HTML output.
	 *
	 * @since 1.7.9
	 *
	 * @param string $output HTML markup to be rendered in place of license settings.
	 */
	return apply_filters( 'wpforms_settings_license_output', $output );
}

/**
 * Settings text input field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_text_callback( $args ) {

	$default = isset( $args['default'] ) ? esc_html( $args['default'] ) : '';
	$value   = wpforms_setting( $args['id'], $default );
	$id      = wpforms_sanitize_key( $args['id'] );

	$output = '<input type="text" id="wpforms-setting-' . $id . '" name="' . $id . '" value="' . esc_attr( $value ) . '">';

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings number input field callback.
 *
 * @since 1.5.3
 *
 * @param array $args Setting field arguments.
 *
 * @return string
 */
function wpforms_settings_number_callback( $args ) {

	$default = isset( $args['default'] ) ? esc_html( $args['default'] ) : '';
	$id      = 'wpforms-setting-' . wpforms_sanitize_key( $args['id'] );
	$attr    =  [
		'value' => wpforms_setting( $args['id'], $default ),
		'name'  => wpforms_sanitize_key( $args['id'] ),
	];
	$data    = ! empty( $args['data'] ) ? $args['data'] : [];

	if ( ! empty( $args['attr'] ) ) {
		$attr = array_merge( $attr, $args['attr'] );
	}

	$output = sprintf(
		'<input type="number" %s>',
		wpforms_html_attributes( $id, [], $data, $attr )
	);

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings select field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_select_callback( $args ) {

	$default     = isset( $args['default'] ) ? esc_html( $args['default'] ) : '';
	$value       = wpforms_setting( $args['id'], $default );
	$id          = wpforms_sanitize_key( $args['id'] );
	$select_name = $id;
	$class       = ! empty( $args['choicesjs'] ) ? 'choicesjs-select' : '';
	$choices     = ! empty( $args['choicesjs'] ) ? true : false;
	$data        = isset( $args['data'] ) ? (array) $args['data'] : [];
	$attr        = isset( $args['attr'] ) ? (array) $args['attr'] : [];

	if ( $choices && ! empty( $args['search'] ) ) {
		$data['search'] = 'true';
	}

	if ( ! empty( $args['placeholder'] ) ) {
		$data['placeholder'] = $args['placeholder'];
	}

	if ( $choices && ! empty( $args['multiple'] ) ) {
		$attr[]      = 'multiple';
		$select_name = $id . '[]';
	}

	foreach ( $data as $name => $val ) {
		$data[ $name ] = 'data-' . sanitize_html_class( $name ) . '="' . esc_attr( $val ) . '"';
	}

	$data = implode( ' ', $data );
	$attr = implode( ' ', array_map( 'sanitize_html_class', $attr ) );

	$output  = $choices ? '<span class="choicesjs-select-wrap">' : '';
	$output .= '<select id="wpforms-setting-' . $id . '" name="' . $select_name . '" class="' . $class . '"' . $data . $attr . '>';

	foreach ( $args['options'] as $option => $name ) {
		if ( empty( $args['selected'] ) ) {
			$selected = selected( $value, $option, false );
		} else {
			$selected = is_array( $args['selected'] ) && in_array( $option, $args['selected'], true ) ? 'selected' : '';
		}
		$output .= '<option value="' . esc_attr( $option ) . '" ' . $selected . '>' . esc_html( $name ) . '</option>';
	}

	$output .= '</select>';
	$output .= $choices ? '</span>' : '';

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings checkbox field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_checkbox_callback( $args ) {

	$value    = wpforms_setting( $args['id'] );
	$id       = wpforms_sanitize_key( $args['id'] );
	$checked  = ! empty( $value ) ? checked( 1, $value, false ) : '';
	$disabled = ! empty( $args['disabled'] ) ? ' disabled' : '';

	$output = '<input type="checkbox" id="wpforms-setting-' . $id . '" name="' . $id . '" ' . $checked . $disabled . '>';

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	if ( ! empty( $args['disabled_desc'] ) ) {
		$output .= '<p class="disabled-desc">' . wp_kses_post( $args['disabled_desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings radio field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_radio_callback( $args ) {

	$default = isset( $args['default'] ) ? esc_html( $args['default'] ) : '';
	$value   = wpforms_setting( $args['id'], $default );
	$id      = wpforms_sanitize_key( $args['id'] );
	$output  = '';
	$x       = 1;

	foreach ( $args['options'] as $option => $name ) {

		$checked = checked( $value, $option, false );
		$output .= '<input type="radio" id="wpforms-setting-' . $id . '[' . $x . ']" name="' . $id . '" value="' . esc_attr( $option ) . '" ' . $checked . '>';
		$output .= '<label for="wpforms-setting-' . $id . '[' . $x . ']" class="option-' . sanitize_html_class( $option ) . '">';
		$output .= esc_html( $name );
		$output .= '</label>';
		$x ++;
	}

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings toggle field callback.
 *
 * @since 1.7.4
 *
 * @param array $args Arguments.
 *
 * @return string
 */
function wpforms_settings_toggle_callback( $args ) {

	$value      = wpforms_setting( $args['id'] );
	$id         = wpforms_sanitize_key( $args['id'] );
	$class      = ! empty( $args['control-class'] ) ? $args['control-class'] : '';
	$class     .= ! empty( $args['is-important'] ) ? ' wpforms-important' : '';
	$input_attr = ! empty( $args['input-attr'] ) ? $args['input-attr'] : '';
	$output     = wpforms_panel_field_toggle_control(
		[
			'control-class' => $class,
		],
		'wpforms-setting-' . $id,
		$id,
		! empty( $args['label'] ) ? $args['label'] : '',
		$value,
		$input_attr
	);

	$desc_on  = ! empty( $args['desc'] ) ? $args['desc'] : '';
	$desc_on  = ! empty( $args['desc-on'] ) ? $args['desc-on'] : $desc_on;
	$desc_off = ! empty( $args['desc-off'] ) ? $args['desc-off'] : '';

	$output .= sprintf(
		'<p class="desc desc-on wpforms-toggle-desc%1$s">%2$s</p>',
		empty( $value ) && ! empty( $desc_off ) ? ' wpforms-hidden' : '',
		wp_kses_post( $desc_on )
	);

	if ( ! empty( $desc_off ) ) {
		$output .= sprintf(
			'<p class="desc desc-off wpforms-toggle-desc%1$s">%2$s</p>',
			empty( $value ) ? '' : ' wpforms-hidden',
			wp_kses_post( $desc_off )
		);
	}

	return $output;
}

/**
 * Settings image upload field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_image_callback( $args ) {

	$default = isset( $args['default'] ) ? esc_html( $args['default'] ) : '';
	$value   = wpforms_setting( $args['id'], $default );
	$id      = wpforms_sanitize_key( $args['id'] );
	$output  = '';

	if ( ! empty( $value ) ) {
		$output .= '<img src="' . esc_url_raw( $value ) . '">';
	}

	$output .= '<input type="text" id="wpforms-setting-' . $id . '" name="' . $id . '" value="' . esc_url_raw( $value ) . '">';
	$output .= '<button class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey">' . esc_html__( 'Upload Image', 'wpforms-lite' ) . '</button>';

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings color picker field callback.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_color_callback( $args ) {

	$default = isset( $args['default'] ) ? esc_html( $args['default'] ) : '';
	$value   = wpforms_setting( $args['id'], $default );
	$id      = wpforms_sanitize_key( $args['id'] );
	$data    = isset( $args['data'] ) ? (array) $args['data'] : [];

	foreach ( $data as $name => $val ) {
		$data[ $name ] = 'data-' . sanitize_html_class( $name ) . '="' . esc_attr( $val ) . '"';
	}

	$data = implode( ' ', $data );

	$output = '<input type="text" id="wpforms-setting-' . $id . '" class="wpforms-color-picker" name="' . $id . '" value="' . esc_attr( $value ) . '" ' . $data . '>';

	if ( ! empty( $args['desc'] ) ) {
		$output .= '<p class="desc">' . wp_kses_post( $args['desc'] ) . '</p>';
	}

	return $output;
}

/**
 * Settings providers field callback - this is for the Integrations tab.
 *
 * @since 1.3.9
 *
 * @param array $args
 *
 * @return string
 */
function wpforms_settings_providers_callback( $args ) {

	$active    = wpforms_get_providers_available();
	$providers = wpforms_get_providers_options();

	$output = '<div id="wpforms-settings-providers">';

	ob_start();
	do_action( 'wpforms_settings_providers', $active, $providers );
	$output .= ob_get_clean();

	$output .= '</div>';

	return $output;
}

/**
 * Settings field columns callback.
 *
 * @since 1.5.8
 *
 * @param array $args Arguments passed by the setting.
 *
 * @return string
 */
function wpforms_settings_columns_callback( $args ) {

	if ( empty( $args['columns'] ) || ! is_array( $args['columns'] ) ) {
		return '';
	}

	$output = '<div class="wpforms-setting-columns">';

	foreach ( $args['columns'] as $column ) {

		// Define default callback for this field type.
		$callback = ! empty( $column['type'] ) ? 'wpforms_settings_' . $column['type'] . '_callback' : '';

		// Allow custom callback to be provided via arg.
		if ( ! empty( $column['callback'] ) ) {
			$callback = $column['callback'];
		}

		$output .= '<div class="wpforms-setting-column">';

		if ( ! empty( $column['name'] ) ) {
			$output .= '<label><b>' . wp_kses_post( $column['name'] ) . '</b></label>';
		}

		if ( function_exists( $callback ) ) {
			$output .= call_user_func( $callback, $column );
		}

		$output .= '</div>';
	}

	$output .= '</div>';

	return $output;
}
