<?php

/**
 * Register and setup WPForms as a Visual Composer element.
 *
 * @since 1.3.0
 */
function wpforms_visual_composer_shortcode() {

	if ( ! is_user_logged_in() ) {
		return;
	}

	$wpf = wpforms()->form->get(
		'',
		[
			'orderby' => 'title',
		]
	);

	if ( ! empty( $wpf ) ) {
		$forms = [
			esc_html__( 'Select a form to display', 'wpforms-lite' ) => '',
		];

		foreach ( $wpf as $form ) {
			$forms[ $form->post_title ] = $form->ID;
		}
	} else {
		$forms = [
			esc_html__( 'No forms found', 'wpforms-lite' ) => '',
		];
	}

	vc_map(
		[
			'name'        => esc_html__( 'WPForms', 'wpforms-lite' ),
			'base'        => 'wpforms',
			'icon'        => WPFORMS_PLUGIN_URL . 'assets/images/sullie-vc.png',
			'category'    => esc_html__( 'Content', 'wpforms-lite' ),
			'description' => esc_html__( 'Add your form', 'wpforms-lite' ),
			'params'      => [
				[
					'type'        => 'dropdown',
					'heading'     => esc_html__( 'Form', 'wpforms-lite' ),
					'param_name'  => 'id',
					'value'       => $forms,
					'save_always' => true,
					'description' => esc_html__( 'Select a form to add it to your post or page.', 'wpforms-lite' ),
					'admin_label' => true,
				],
				[
					'type'        => 'dropdown',
					'heading'     => esc_html__( 'Display Form Name', 'wpforms-lite' ),
					'param_name'  => 'title',
					'value'       => [
						esc_html__( 'No', 'wpforms-lite' )  => 'false',
						esc_html__( 'Yes', 'wpforms-lite' ) => 'true',
					],
					'save_always' => true,
					'description' => esc_html__( 'Would you like to display the forms name?', 'wpforms-lite' ),
					'dependency'  => [
						'element'   => 'id',
						'not_empty' => true,
					],
				],
				[
					'type'        => 'dropdown',
					'heading'     => esc_html__( 'Display Form Description', 'wpforms-lite' ),
					'param_name'  => 'description',
					'value'       => [
						esc_html__( 'No', 'wpforms-lite' )  => 'false',
						esc_html__( 'Yes', 'wpforms-lite' ) => 'true',
					],
					'save_always' => true,
					'description' => esc_html__( 'Would you like to display the form description?', 'wpforms-lite' ),
					'dependency'  => [
						'element'   => 'id',
						'not_empty' => true,
					],
				],
			],
		]
	);
}
add_action( 'vc_before_init', 'wpforms_visual_composer_shortcode' );

/**
 * Load our basic CSS when in Visual Composer's frontend editor.
 *
 * @since 1.3.0
 */
function wpforms_visual_composer_shortcode_css() {

	// Load CSS per global setting.
	if ( wpforms_setting( 'disable-css', '1' ) === '1' ) {
		wp_enqueue_style(
			'wpforms-full',
			WPFORMS_PLUGIN_URL . 'assets/css/frontend/classic/wpforms-full.css',
			[],
			WPFORMS_VERSION
		);
	}

	if ( wpforms_setting( 'disable-css', '1' ) === '2' ) {
		wp_enqueue_style(
			'wpforms-base',
			WPFORMS_PLUGIN_URL . 'assets/css/wpforms-base.css',
			[],
			WPFORMS_VERSION
		);
	}
}
add_action( 'vc_load_iframe_jscss', 'wpforms_visual_composer_shortcode_css' );
