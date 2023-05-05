<?php
/**
 * Module Name: Sharing
 * Module Description: Add Twitter and Facebook buttons at the bottom of each post, making it easy for visitors to share your content.
 * Sort Order: 7
 * Recommendation Order: 6
 * First Introduced: 1.1
 * Major Changes In: 1.2
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Social, Recommended
 * Feature: Engagement
 * Additional Search Queries: share, sharing, sharedaddy, social buttons, buttons, share facebook, share twitter, social media sharing, social media share, social share, icons, email, facebook, twitter, linkedin, pinterest, pocket, social widget, social media
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status;

if ( ! function_exists( 'sharing_init' ) ) {
	require __DIR__ . '/sharedaddy/sharedaddy.php';
}

add_action( 'jetpack_modules_loaded', 'sharedaddy_loaded' );

/**
 * Sharing module code loaded after all modules have been loaded.
 */
function sharedaddy_loaded() {
	Jetpack::enable_module_configurable( __FILE__ );
	add_filter( 'jetpack_module_configuration_url_sharedaddy', 'jetpack_sharedaddy_configuration_url' );
}

/**
 * Return Jetpack Sharing configuration URL
 *
 * @return string Sharing config URL
 */
function jetpack_sharedaddy_configuration_url() {
	$status = new Status();
	if ( $status->is_offline_mode() || $status->is_staging_site() || ! ( new Connection_Manager( 'jetpack' ) )->is_user_connected() ) {
		return admin_url( 'options-general.php?page=sharing' );
	}

	return Redirect::get_url( 'calypso-marketing-sharing-buttons' );
}
