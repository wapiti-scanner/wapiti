<?php

add_action(
	'init',
	'wpcf7_init_block_editor_assets',
	10, 0
);

function wpcf7_init_block_editor_assets() {
	$assets = array();

	$asset_file = wpcf7_plugin_path(
		'includes/block-editor/index.asset.php'
	);

	if ( file_exists( $asset_file ) ) {
		$assets = include( $asset_file );
	}

	$assets = wp_parse_args( $assets, array(
		'dependencies' => array(
			'wp-api-fetch',
			'wp-block-editor',
			'wp-blocks',
			'wp-components',
			'wp-element',
			'wp-i18n',
			'wp-url',
		),
		'version' => WPCF7_VERSION,
	) );

	wp_register_script(
		'contact-form-7-block-editor',
		wpcf7_plugin_url( 'includes/block-editor/index.js' ),
		$assets['dependencies'],
		$assets['version']
	);

	wp_set_script_translations(
		'contact-form-7-block-editor',
		'contact-form-7'
	);

	register_block_type(
		wpcf7_plugin_path( 'includes/block-editor' ),
		array(
			'editor_script' => 'contact-form-7-block-editor',
		)
	);
}


add_action(
	'enqueue_block_editor_assets',
	'wpcf7_enqueue_block_editor_assets',
	10, 0
);

function wpcf7_enqueue_block_editor_assets() {
	$contact_forms = array_map(
		function ( $contact_form ) {
			return array(
				'id' => $contact_form->id(),
				'slug' => $contact_form->name(),
				'title' => $contact_form->title(),
				'locale' => $contact_form->locale(),
			);
		},
		WPCF7_ContactForm::find( array(
			'posts_per_page' => 20,
			'orderby' => 'modified',
			'order' => 'DESC',
		) )
	);

	wp_add_inline_script(
		'contact-form-7-block-editor',
		sprintf(
			'window.wpcf7 = {contactForms:%s};',
			json_encode( $contact_forms )
		),
		'before'
	);
}
