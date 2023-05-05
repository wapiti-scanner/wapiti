<?php
/**
 * A Path & URL utility class for Jetpack.
 *
 * @package automattic/jetpack-status
 */

namespace Automattic\Jetpack;

/**
 * Class Automattic\Jetpack\Paths
 *
 * Used to retrieve information about files.
 */
class Paths {
	/**
	 * Jetpack Admin URL.
	 *
	 * @param array $args Query string args.
	 *
	 * @return string Jetpack admin URL.
	 */
	public function admin_url( $args = null ) {
		$args = wp_parse_args( $args, array( 'page' => 'jetpack' ) );
		$url  = add_query_arg( $args, admin_url( 'admin.php' ) );
		return $url;
	}
}
