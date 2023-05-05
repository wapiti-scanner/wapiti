<?php // phpcs:disable Squiz.Commenting.FileComment.Missing
/**
 * Memberships block.
 *
 * @since 7.3.0
 *
 * @package automattic/jetpack
 */

if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || Jetpack::is_connection_ready() ) {
	require_once JETPACK__PLUGIN_DIR . '/modules/memberships/class-jetpack-memberships.php';
	Jetpack_Memberships::get_instance()->register_gutenberg_block();
}
