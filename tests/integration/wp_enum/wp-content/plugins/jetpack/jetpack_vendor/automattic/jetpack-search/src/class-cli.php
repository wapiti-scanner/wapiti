<?php
/**
 * CLI class exposed by WPCLI
 *
 * @package    automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

use \WP_CLI;
use \WP_CLI_Command;
use \WP_Error;

if ( ! class_exists( 'WP_CLI_Command' ) ) {
	return;
}

/**
 * Provide functionality by WPCLI.
 */
class CLI extends WP_CLI_Command {
	/**
	 * Auto config instant search, including set result format, set up overlay widgets and add a search input to the home page thru widgets or blocks.
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack-search auto_config user_login
	 *
	 * wp jetpack-search auto_config user_id
	 *
	 * @param array $args - Args passsed in.
	 */
	public function auto_config( $args ) {
		try {
			if ( empty( $args ) ) {
				WP_CLI::error( 'A user login or ID is required.' );
			}

			// Some functions may require admin capabilities to run.
			$ret = $this->set_user( $args[0] );
			if ( is_wp_error( $ret ) ) {
				WP_CLI::error( $ret->get_error_message() );
			}

			WP_CLI::line( 'Running as user ' . $ret->user_login . '…' );
			$blog_id = Helper::get_wpcom_site_id();
			Instant_Search::instance( $blog_id )->auto_config_search();
			WP_CLI::success( 'Auto config success!' );
		} catch ( \Exception $e ) {
			WP_CLI::error( $e->getMessage() );
		}
	}

	/**
	 * Set current user by ID or login
	 *
	 * @param string|int $user User ID or login.
	 */
	protected function set_user( $user ) {
		$get_user_by = 'login';
		if ( filter_var( $user, FILTER_VALIDATE_INT ) > 0 ) {
			$get_user_by = 'ID';
		}
		$user_info = get_user_by( $get_user_by, (string) $user );
		if ( ! $user_info ) {
			return new WP_Error( 'user_not_found', "Could not find user '{$user}' by {$get_user_by}." );
		}
		return wp_set_current_user( $user_info->ID );
	}
}
