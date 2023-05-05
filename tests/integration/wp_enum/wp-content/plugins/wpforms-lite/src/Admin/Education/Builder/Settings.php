<?php

namespace WPForms\Admin\Education\Builder;

use \WPForms\Admin\Education;

/**
 * Builder/Settings Education feature.
 *
 * @since 1.6.6
 */
class Settings extends Education\Builder\Panel {

	/**
	 * Panel slug.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 **/
	protected function get_name() {

		return 'settings';
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_filter( 'wpforms_builder_settings_sections', [ $this, 'filter_addons' ], 1 );
		add_action( 'wpforms_builder_after_panel_sidebar', [ $this, 'display' ], 100, 2 );
	}

	/**
	 * Display settings addons.
	 *
	 * @since 1.6.6
	 *
	 * @param object $form  Current form.
	 * @param string $panel Panel slug.
	 */
	public function display( $form, $panel ) {

		if ( empty( $form ) || $this->get_name() !== $panel ) {
			return;
		}

		$this->display_addons();
	}

	/**
	 * Ensure that we do not display activated addon items if those addons are not allowed according to the current license.
	 *
	 * @since 1.6.6
	 *
	 * @param array $sections Settings sections.
	 *
	 * @return array
	 */
	public function filter_addons( $sections ) {

		$this->filter_not_allowed_addons( 'wpforms_builder_settings_sections' );

		return $sections;
	}
}
