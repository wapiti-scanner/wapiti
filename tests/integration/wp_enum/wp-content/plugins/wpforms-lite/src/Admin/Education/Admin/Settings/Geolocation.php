<?php

namespace WPForms\Admin\Education\Admin\Settings;

use WPForms\Admin\Education\AddonsItemBase;

/**
 * Admin/Settings/Geolocation Education feature for Lite and Pro.
 *
 * @since 1.6.6
 */
class Geolocation extends AddonsItemBase {

	/**
	 * Slug.
	 *
	 * @since 1.6.6
	 */
	const SLUG = 'geolocation';

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_filter( 'wpforms_settings_defaults', [ $this, 'add_sections' ] );
	}

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'settings', 'geolocation' );
	}

	/**
	 * Enqueues.
	 *
	 * @since 1.6.6
	 */
	public function enqueues() {

		// Lity - lightbox for images.
		wp_enqueue_style(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.css',
			null,
			'3.0.0'
		);

		wp_enqueue_script(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.js',
			[ 'jquery' ],
			'3.0.0',
			true
		);
	}

	/**
	 * Preview of education features for customers with not enough permissions.
	 *
	 * @since 1.6.6
	 *
	 * @param array $settings Settings sections.
	 *
	 * @return array
	 */
	public function add_sections( $settings ) {

		$addon = $this->addons->get_addon( 'geolocation' );

		if (
			empty( $addon ) ||
			empty( $addon['status'] ) ||
			empty( $addon['action'] )
		) {
			return $settings;
		}

		$section_rows = [
			'heading',
			'screenshots',
			'caps',
			'submit',
		];

		foreach ( $section_rows as $section_row ) {
			$settings[ self::SLUG ][ self::SLUG . '-' . $section_row ] = [
				'id'       => self::SLUG . '-' . $section_row,
				'content'  => wpforms_render( 'education/admin/settings/geolocation/' . $section_row, $addon, true ),
				'type'     => 'content',
				'no_label' => true,
				'class'    => [ $section_row, 'wpforms-setting-row-education' ],
			];
		}

		return $settings;
	}
}
