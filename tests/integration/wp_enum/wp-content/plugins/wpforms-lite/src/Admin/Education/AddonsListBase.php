<?php

namespace WPForms\Admin\Education;

/**
 * Base class for all "addons list" type Education features.
 *
 * @since 1.6.6
 */
abstract class AddonsListBase extends AddonsItemBase {

	/**
	 * Display addons.
	 *
	 * @since 1.6.6
	 */
	public function display_addons() {

		array_map( [ $this, 'display_single_addon' ], (array) $this->get_addons() );
	}

	/**
	 * Get addons.
	 *
	 * @since 1.6.6
	 *
	 * @return array Addons array.
	 */
	abstract protected function get_addons();

	/**
	 * Ensure that we do not display activated addon items if those addons are not allowed according to the current license.
	 *
	 * @since 1.6.6
	 *
	 * @param string $hook Hook name.
	 */
	protected function filter_not_allowed_addons( $hook ) {

		$edu_addons = wp_list_pluck( $this->get_addons(), 'slug' );

		foreach ( $edu_addons as $i => $addon ) {
			$edu_addons[ $i ] = strtolower( preg_replace( '/[^a-zA-Z0-9]+/', '', $addon ) );
		}

		if ( empty( $GLOBALS['wp_filter'][ $hook ]->callbacks ) ) {
			return;
		}

		foreach ( $GLOBALS['wp_filter'][ $hook ]->callbacks as $priority => $hooks ) {
			foreach ( $hooks as $name => $arr ) {
				$class = ! empty( $arr['function'][0] ) && is_object( $arr['function'][0] ) ? strtolower( get_class( $arr['function'][0] ) ) : '';
				$class = explode( '\\', $class )[0];
				$class = preg_replace( '/[^a-zA-Z0-9]+/', '', $class );

				if ( in_array( $class, $edu_addons, true ) ) {
					unset( $GLOBALS['wp_filter'][ $hook ]->callbacks[ $priority ][ $name ] );
				}
			}
		}
	}
}
