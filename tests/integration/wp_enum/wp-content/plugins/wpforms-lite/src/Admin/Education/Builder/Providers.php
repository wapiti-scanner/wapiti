<?php

namespace WPForms\Admin\Education\Builder;

use \WPForms\Admin\Education;

/**
 * Builder/Providers Education feature.
 *
 * @since 1.6.6
 */
class Providers extends Education\Builder\Panel {

	/**
	 * Panel slug.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 **/
	protected function get_name() {

		return 'providers';
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wpforms_providers_panel_sidebar', [ $this, 'filter_addons' ], 1 );
		add_action( 'wpforms_providers_panel_sidebar', [ $this, 'display_addons' ], 500 );
	}

	/**
	 * Ensure that we do not display activated addon items if those addons are not allowed according to the current license.
	 *
	 * @since 1.6.6
	 */
	public function filter_addons() {

		$this->filter_not_allowed_addons( 'wpforms_providers_panel_sidebar' );
	}

	/**
	 * Get addons for the Marketing panel.
	 *
	 * @since 1.7.7.2
	 */
	protected function get_addons() {

		$addons = parent::get_addons();

		/**
		 * Google Sheets uses Providers API. All providers are automatically
		 * added to the Marketing tab in the builder. We don't need the addon
		 * on the Marketing tab because the addon is already added to
		 * the builder's Settings tab.
		 */
		foreach ( $addons as $key => $addon ) {
			if ( isset( $addon['slug'] ) && $addon['slug'] === 'wpforms-google-sheets' ) {
				unset( $addons[ $key ] );
				break;
			}
		}

		return $addons;
	}
}
