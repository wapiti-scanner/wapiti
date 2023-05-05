<?php
/**
 * Globally registers the 'genericons' style and font.
 *
 * This ensures any theme or plugin using it is on the latest version of Genericons, and helps to avoid conflicts.
 *
 * @package automattic/jetpack
 */

add_action( 'init', 'jetpack_register_genericons', 1 );

/**
 * Registers Genericons if not already done so by other code.
 */
function jetpack_register_genericons() {
	if ( ! wp_style_is( 'genericons', 'registered' ) ) {
		wp_register_style( 'genericons', plugins_url( 'genericons/genericons/genericons.css', __FILE__ ), false, '3.1' );
	}
}
