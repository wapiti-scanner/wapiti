<?php

namespace WPForms\Admin\Education\Builder;

use \WPForms\Admin\Education;

/**
 * Builder/Payments Education feature.
 *
 * @since 1.6.6
 */
class Payments extends Education\Builder\Panel {

	/**
	 * Panel slug.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 **/
	protected function get_name() {

		return 'payments';
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wpforms_payments_panel_sidebar', [ $this, 'filter_addons' ], 1 );
		add_action( 'wpforms_payments_panel_sidebar', [ $this, 'display_addons' ], 500 );
	}

	/**
	 * Get addons for the Payments panel.
	 *
	 * @since 1.7.7.2
	 *
	 * @return array
	 */
	protected function get_addons() {

		$addons = $this->addons->get_by_category( $this->get_name() );

		// Make Stripe at the top of the list.
		foreach ( $addons as $key => $addon ) {

			if ( $addon['slug'] !== 'wpforms-stripe' ) {
				continue;
			}

			$addon['recommended'] = true;

			unset( $addons[ $key ] );
			array_unshift( $addons, $addon );
			break;
		}

		return $addons;
	}

	/**
	 * Template name for rendering single addon item.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	protected function get_single_addon_template() {

		return 'education/builder/providers-item';
	}

	/**
	 * Ensure that we do not display activated addon items if those addons are not allowed according to the current license.
	 *
	 * @since 1.6.6
	 */
	public function filter_addons() {

		$this->filter_not_allowed_addons( 'wpforms_payments_panel_sidebar' );
	}
}
