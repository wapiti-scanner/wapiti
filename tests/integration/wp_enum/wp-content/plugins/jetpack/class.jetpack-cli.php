<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * WP-CLI command class.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Connection\Tokens;
use Automattic\Jetpack\Identity_Crisis;
use Automattic\Jetpack\IP\Utils as IP_Utils;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Sync\Actions;
use Automattic\Jetpack\Sync\Listener;
use Automattic\Jetpack\Sync\Modules;
use Automattic\Jetpack\Sync\Queue;
use Automattic\Jetpack\Sync\Settings;
use Automattic\Jetpack\Waf\Brute_Force_Protection\Brute_Force_Protection_Shared_Functions;

if ( ! class_exists( 'WP_CLI_Command' ) ) {
	return;
}

WP_CLI::add_command( 'jetpack', 'Jetpack_CLI' );

/**
 * Control your local Jetpack installation.
 */
class Jetpack_CLI extends WP_CLI_Command {
	/**
	 * Console escape code for green.
	 *
	 * @var string
	 */
	public $green_open = "\033[32m";

	/**
	 * Console escape code for red.
	 *
	 * @var string
	 */
	public $red_open = "\033[31m";

	/**
	 * Console escape code for yellow.
	 *
	 * @var string
	 */
	public $yellow_open = "\033[33m";

	/**
	 * Console escape code to reset coloring.
	 *
	 * @var string
	 */
	public $color_close = "\033[0m";

	/**
	 * Get Jetpack Details
	 *
	 * ## OPTIONS
	 *
	 * empty: Leave it empty for basic stats
	 *
	 * full: View full stats.  It's the data from the heartbeat
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack status
	 * wp jetpack status full
	 *
	 * @param array $args Positional args.
	 */
	public function status( $args ) {
		require_once JETPACK__PLUGIN_DIR . '_inc/lib/debugger.php';

		/* translators: %s is the site URL */
		WP_CLI::line( sprintf( __( 'Checking status for %s', 'jetpack' ), esc_url( get_home_url() ) ) );

		if ( isset( $args[0] ) && 'full' !== $args[0] ) {
			/* translators: %s is a command like "prompt" */
			WP_CLI::error( sprintf( __( '%s is not a valid command.', 'jetpack' ), $args[0] ) );
		}

		$master_user_email = Jetpack::get_master_user_email();

		$cxntests = new Jetpack_Cxn_Tests();

		if ( $cxntests->pass() ) {
			$cxntests->output_results_for_cli();

			WP_CLI::success( __( 'Jetpack is currently connected to WordPress.com', 'jetpack' ) );
		} else {
			$error = array();
			foreach ( $cxntests->list_fails() as $fail ) {
				$error[] = $fail['name'] . ( empty( $fail['message'] ) ? '' : ': ' . $fail['message'] );
			}
			WP_CLI::error_multi_line( $error );

			$cxntests->output_results_for_cli();

			WP_CLI::error( __( 'One or more tests did not pass. Please investigate!', 'jetpack' ) ); // Exit CLI.
		}

		/* translators: %s is current version of Jetpack, for example 7.3 */
		WP_CLI::line( sprintf( __( 'The Jetpack Version is %s', 'jetpack' ), JETPACK__VERSION ) );
		/* translators: %d is WP.com ID of this blog */
		WP_CLI::line( sprintf( __( 'The WordPress.com blog_id is %d', 'jetpack' ), Jetpack_Options::get_option( 'id' ) ) );
		/* translators: %s is the email address of the connection owner */
		WP_CLI::line( sprintf( __( 'The WordPress.com account for the primary connection is %s', 'jetpack' ), $master_user_email ) );

		/*
		 * Are they asking for all data?
		 *
		 * Loop through heartbeat data and organize by priority.
		 */
		$all_data = ( isset( $args[0] ) && 'full' === $args[0] ) ? 'full' : false;
		if ( $all_data ) {
			// Heartbeat data.
			WP_CLI::line( "\n" . __( 'Additional data: ', 'jetpack' ) );

			// Get the filtered heartbeat data.
			// Filtered so we can color/list by severity.
			$stats = Jetpack::jetpack_check_heartbeat_data();

			// Display red flags first.
			foreach ( $stats['bad'] as $stat => $value ) {
				WP_CLI::line( sprintf( "$this->red_open%-'.16s %s $this->color_close", $stat, $value ) );
			}

			// Display caution warnings next.
			foreach ( $stats['caution'] as $stat => $value ) {
				WP_CLI::line( sprintf( "$this->yellow_open%-'.16s %s $this->color_close", $stat, $value ) );
			}

			// The rest of the results are good!
			foreach ( $stats['good'] as $stat => $value ) {

				// Modules should get special spacing for aestetics.
				if ( strpos( $stat, 'odule-' ) ) {
					WP_CLI::line( sprintf( "%-'.30s %s", $stat, $value ) );
					usleep( 4000 ); // For dramatic effect lolz.
					continue;
				}
				WP_CLI::line( sprintf( "%-'.16s %s", $stat, $value ) );
				usleep( 4000 ); // For dramatic effect lolz.
			}
		} else {
			// Just the basics.
			WP_CLI::line( "\n" . _x( "View full status with 'wp jetpack status full'", '"wp jetpack status full" is a command - do not translate', 'jetpack' ) );
		}
	}

	/**
	 * Tests the active connection
	 *
	 * Does a two-way test to verify that the local site can communicate with remote Jetpack/WP.com servers and that Jetpack/WP.com servers can talk to the local site.
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack test-connection
	 *
	 * @subcommand test-connection
	 */
	public function test_connection() {

		/* translators: %s is the site URL */
		WP_CLI::line( sprintf( __( 'Testing connection for %s', 'jetpack' ), esc_url( get_site_url() ) ) );

		if ( ! Jetpack::is_connection_ready() ) {
			WP_CLI::error( __( 'Jetpack is not currently connected to WordPress.com', 'jetpack' ) );
		}

		$response = Client::wpcom_json_api_request_as_blog(
			sprintf( '/jetpack-blogs/%d/test-connection', Jetpack_Options::get_option( 'id' ) ),
			Client::WPCOM_JSON_API_VERSION
		);

		if ( is_wp_error( $response ) ) {
			/* translators: %1$s is the error code, %2$s is the error message */
			WP_CLI::error( sprintf( __( 'Failed to test connection (#%1$s: %2$s)', 'jetpack' ), $response->get_error_code(), $response->get_error_message() ) );
		}

		$body = wp_remote_retrieve_body( $response );
		if ( ! $body ) {
			WP_CLI::error( __( 'Failed to test connection (empty response body)', 'jetpack' ) );
		}

		$result       = json_decode( $body );
		$is_connected = (bool) $result->connected;
		$message      = $result->message;

		if ( $is_connected ) {
			WP_CLI::success( $message );
		} else {
			WP_CLI::error( $message );
		}
	}

	/**
	 * Disconnect Jetpack Blogs or Users
	 *
	 * ## OPTIONS
	 *
	 * blog: Disconnect the entire blog.
	 *
	 * user <user_identifier>: Disconnect a specific user from WordPress.com.
	 *
	 * [--force]
	 * If the user ID provided is the connection owner, it will only be disconnected if --force is passed
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack disconnect blog
	 * wp jetpack disconnect user 13
	 * wp jetpack disconnect user 1 --force
	 * wp jetpack disconnect user username
	 * wp jetpack disconnect user email@domain.com
	 *
	 * @synopsis <blog|user> [<user_identifier>] [--force]
	 *
	 * @param array $args Positional args.
	 * @param array $assoc_args Named args.
	 */
	public function disconnect( $args, $assoc_args ) {
		if ( ! Jetpack::is_connection_ready() ) {
			WP_CLI::success( __( 'The site is not currently connected, so nothing to do!', 'jetpack' ) );
			return;
		}

		$action = isset( $args[0] ) ? $args[0] : 'prompt';
		if ( ! in_array( $action, array( 'blog', 'user', 'prompt' ), true ) ) {
			/* translators: %s is a command like "prompt" */
			WP_CLI::error( sprintf( __( '%s is not a valid command.', 'jetpack' ), $action ) );
		}

		if ( in_array( $action, array( 'user' ), true ) ) {
			if ( isset( $args[1] ) ) {
				$user_id = $args[1];
				if ( ctype_digit( $user_id ) ) {
					$field   = 'id';
					$user_id = (int) $user_id;
				} elseif ( is_email( $user_id ) ) {
					$field   = 'email';
					$user_id = sanitize_user( $user_id, true );
				} else {
					$field   = 'login';
					$user_id = sanitize_user( $user_id, true );
				}
				$user = get_user_by( $field, $user_id );
				if ( ! $user ) {
					WP_CLI::error( __( 'Please specify a valid user.', 'jetpack' ) );
				}
			} else {
				WP_CLI::error( __( 'Please specify a user by either ID, username, or email.', 'jetpack' ) );
			}
		}

		$force_user_disconnect = ! empty( $assoc_args['force'] );

		switch ( $action ) {
			case 'blog':
				Jetpack::log( 'disconnect' );
				( new Connection_Manager( 'jetpack' ) )->disconnect_site();
				WP_CLI::success(
					sprintf(
						/* translators: %s is the site URL */
						__( 'Jetpack has been successfully disconnected for %s.', 'jetpack' ),
						esc_url( get_site_url() )
					)
				);
				break;
			case 'user':
				$connection_manager = new Connection_Manager( 'jetpack' );
				$disconnected       = $connection_manager->disconnect_user( $user->ID, $force_user_disconnect );
				if ( $disconnected ) {
					Jetpack::log( 'unlink', $user->ID );
					WP_CLI::success( __( 'User has been successfully disconnected.', 'jetpack' ) );
				} else {
					if ( ! $connection_manager->is_user_connected( $user->ID ) ) {
						/* translators: %s is a username */
						$error_message = sprintf( __( 'User %s could not be disconnected because it is not connected!', 'jetpack' ), "{$user->data->user_login} <{$user->data->user_email}>" );
					} elseif ( ! $force_user_disconnect && $connection_manager->is_connection_owner( $user->ID ) ) {
						/* translators: %s is a username */
						$error_message = sprintf( __( 'User %s could not be disconnected because it is the connection owner! If you want to disconnect in anyway, use the --force parameter.', 'jetpack' ), "{$user->data->user_login} <{$user->data->user_email}>" );
					} else {
						/* translators: %s is a username */
						$error_message = sprintf( __( 'User %s could not be disconnected.', 'jetpack' ), "{$user->data->user_login} <{$user->data->user_email}>" );
					}
					WP_CLI::error( $error_message );
				}
				break;
			case 'prompt':
				WP_CLI::error( __( 'Please specify if you would like to disconnect a blog or user.', 'jetpack' ) );
				break;
		}
	}

	/**
	 * Reset Jetpack options and settings to default
	 *
	 * ## OPTIONS
	 *
	 * modules: Resets modules to default state ( get_default_modules() )
	 *
	 * options: Resets all Jetpack options except:
	 *  - All private options (Blog token, user token, etc...)
	 *  - id (The Client ID/WP.com Blog ID of this site)
	 *  - master_user
	 *  - version
	 *  - activated
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack reset options
	 * wp jetpack reset modules
	 * wp jetpack reset sync-checksum --dry-run --offset=0
	 *
	 * @synopsis <modules|options|sync-checksum> [--dry-run] [--offset=<offset>]
	 *
	 * @param array $args Positional args.
	 * @param array $assoc_args Named args.
	 */
	public function reset( $args, $assoc_args ) {
		$action = isset( $args[0] ) ? $args[0] : 'prompt';
		if ( ! in_array( $action, array( 'options', 'modules', 'sync-checksum' ), true ) ) {
			/* translators: %s is a command like "prompt" */
			WP_CLI::error( sprintf( __( '%s is not a valid command.', 'jetpack' ), $action ) );
		}

		$is_dry_run = ! empty( $assoc_args['dry-run'] );

		if ( $is_dry_run ) {
			WP_CLI::warning(
				__( "\nThis is a dry run.\n", 'jetpack' ) .
				__( "No actions will be taken.\n", 'jetpack' ) .
				__( "The following messages will give you preview of what will happen when you run this command.\n\n", 'jetpack' )
			);
		} else {
			// We only need to confirm "Are you sure?" when we are not doing a dry run.
			jetpack_cli_are_you_sure();
		}

		switch ( $action ) {
			case 'options':
				$options_to_reset = Jetpack_Options::get_options_for_reset();
				// Reset the Jetpack options.
				WP_CLI::line(
					sprintf(
						/* translators: %s is the site URL */
						__( "Resetting Jetpack Options for %s...\n", 'jetpack' ),
						esc_url( get_site_url() )
					)
				);
				sleep( 1 ); // Take a breath.
				foreach ( $options_to_reset['jp_options'] as $option_to_reset ) {
					if ( ! $is_dry_run ) {
						Jetpack_Options::delete_option( $option_to_reset );
						usleep( 100000 );
					}

					/* translators: This is the result of an action. The option named %s was reset */
					WP_CLI::success( sprintf( __( '%s option reset', 'jetpack' ), $option_to_reset ) );
				}

				// Reset the WP options.
				WP_CLI::line( __( "Resetting the jetpack options stored in wp_options...\n", 'jetpack' ) );
				usleep( 500000 ); // Take a breath.
				foreach ( $options_to_reset['wp_options'] as $option_to_reset ) {
					if ( ! $is_dry_run ) {
						delete_option( $option_to_reset );
						usleep( 100000 );
					}
					/* translators: This is the result of an action. The option named %s was reset */
					WP_CLI::success( sprintf( __( '%s option reset', 'jetpack' ), $option_to_reset ) );
				}

				// Reset to default modules.
				WP_CLI::line( __( "Resetting default modules...\n", 'jetpack' ) );
				usleep( 500000 ); // Take a breath.
				$default_modules = Jetpack::get_default_modules();
				if ( ! $is_dry_run ) {
					Jetpack::update_active_modules( $default_modules );
				}
				WP_CLI::success( __( 'Modules reset to default.', 'jetpack' ) );
				break;
			case 'modules':
				if ( ! $is_dry_run ) {
					$default_modules = Jetpack::get_default_modules();
					Jetpack::update_active_modules( $default_modules );
				}

				WP_CLI::success( __( 'Modules reset to default.', 'jetpack' ) );
				break;
			case 'prompt':
				WP_CLI::error( __( 'Please specify if you would like to reset your options, modules or sync-checksum', 'jetpack' ) );
				break;
			case 'sync-checksum':
				$option = 'jetpack_callables_sync_checksum';

				if ( is_multisite() ) {
					$offset = isset( $assoc_args['offset'] ) ? (int) $assoc_args['offset'] : 0;

					/*
					 * 1000 is a good limit since we don't expect the number of sites to be more than 1000
					 * Offset can be used to paginate and try to clean up more sites.
					 */
					$sites       = get_sites(
						array(
							'number' => 1000,
							'offset' => $offset,
						)
					);
					$count_fixes = 0;
					foreach ( $sites as $site ) {
						switch_to_blog( $site->blog_id );
						$count = self::count_option( $option );
						if ( $count > 1 ) {
							if ( ! $is_dry_run ) {
								delete_option( $option );
							}
							WP_CLI::line(
								sprintf(
									/* translators: %1$d is a number, %2$s is the name of an option, %2$s is the site URL. */
									__( 'Deleted %1$d %2$s options from %3$s', 'jetpack' ),
									$count,
									$option,
									"{$site->domain}{$site->path}"
								)
							);
							++$count_fixes;
							if ( ! $is_dry_run ) {
								/*
								 * We could be deleting a lot of options rows at the same time.
								 * Allow some time for replication to catch up.
								 */
								sleep( 3 );
							}
						}

						restore_current_blog();
					}
					if ( $count_fixes ) {
						WP_CLI::success(
							sprintf(
								/* translators: %1$s is the name of an option, %2$d is a number of sites. */
								__( 'Successfully reset %1$s on %2$d sites.', 'jetpack' ),
								$option,
								$count_fixes
							)
						);
					} else {
						WP_CLI::success( __( 'No options were deleted.', 'jetpack' ) );
					}
					return;
				}

				$count = self::count_option( $option );
				if ( $count > 1 ) {
					if ( ! $is_dry_run ) {
						delete_option( $option );
					}
					WP_CLI::success(
						sprintf(
							/* translators: %1$d is a number, %2$s is the name of an option. */
							__( 'Deleted %1$d %2$s options', 'jetpack' ),
							$count,
							$option
						)
					);
					return;
				}

				WP_CLI::success( __( 'No options were deleted.', 'jetpack' ) );
				break;

		}
	}

	/**
	 * Return the number of times an option appears
	 * Normally an option would only appear 1 since the option key is supposed to be unique
	 * but if a site hasn't updated the DB schema then that would not be the case.
	 *
	 * @param string $option Option name.
	 *
	 * @return int
	 */
	private static function count_option( $option ) {
		global $wpdb;
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $wpdb->options WHERE option_name = %s",
				$option
			)
		);
	}

	/**
	 * Manage Jetpack Modules
	 *
	 * ## OPTIONS
	 *
	 * <list|activate|deactivate|toggle>
	 * : The action to take.
	 * ---
	 * default: list
	 * options:
	 *  - list
	 *  - activate
	 *  - deactivate
	 *  - toggle
	 * ---
	 *
	 * [<module_slug>]
	 * : The slug of the module to perform an action on.
	 *
	 * [--format=<format>]
	 * : Allows overriding the output of the command when listing modules.
	 * ---
	 * default: table
	 * options:
	 *  - table
	 *  - json
	 *  - csv
	 *  - yaml
	 *  - ids
	 *  - count
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack module list
	 * wp jetpack module list --format=json
	 * wp jetpack module activate stats
	 * wp jetpack module deactivate stats
	 * wp jetpack module toggle stats
	 * wp jetpack module activate all
	 * wp jetpack module deactivate all
	 *
	 * @param array $args Positional args.
	 * @param array $assoc_args Named args.
	 */
	public function module( $args, $assoc_args ) {
		$action = isset( $args[0] ) ? $args[0] : 'list';

		if ( isset( $args[1] ) ) {
			$module_slug = $args[1];
			if ( 'all' !== $module_slug && ! Jetpack::is_module( $module_slug ) ) {
				/* translators: %s is a module slug like "stats" */
				WP_CLI::error( sprintf( __( '%s is not a valid module.', 'jetpack' ), $module_slug ) );
			}
			if ( 'toggle' === $action ) {
				$action = Jetpack::is_module_active( $module_slug )
					? 'deactivate'
					: 'activate';
			}
			if ( 'all' === $args[1] ) {
				$action = ( 'deactivate' === $action )
					? 'deactivate_all'
					: 'activate_all';
			}
		} elseif ( 'list' !== $action ) {
			WP_CLI::line( __( 'Please specify a valid module.', 'jetpack' ) );
			$action = 'list';
		}

		switch ( $action ) {
			case 'list':
				$modules_list = array();
				$modules      = Jetpack::get_available_modules();
				sort( $modules );
				foreach ( (array) $modules as $module_slug ) {
					if ( 'vaultpress' === $module_slug ) {
						continue;
					}
					$modules_list[] = array(
						'slug'   => $module_slug,
						'status' => Jetpack::is_module_active( $module_slug )
							? __( 'Active', 'jetpack' )
							: __( 'Inactive', 'jetpack' ),
					);
				}
				WP_CLI\Utils\format_items( $assoc_args['format'], $modules_list, array( 'slug', 'status' ) );
				break;
			case 'activate':
				$module = Jetpack::get_module( $module_slug );
				Jetpack::log( 'activate', $module_slug );
				if ( Jetpack::activate_module( $module_slug, false, false ) ) {
					/* translators: %s is the name of a Jetpack module */
					WP_CLI::success( sprintf( __( '%s has been activated.', 'jetpack' ), $module['name'] ) );
				} else {
					/* translators: %s is the name of a Jetpack module */
					WP_CLI::error( sprintf( __( '%s could not be activated.', 'jetpack' ), $module['name'] ) );
				}
				break;
			case 'activate_all':
				$modules = Jetpack::get_available_modules();
				Jetpack::update_active_modules( $modules );
				WP_CLI::success( __( 'All modules activated!', 'jetpack' ) );
				break;
			case 'deactivate':
				$module = Jetpack::get_module( $module_slug );
				Jetpack::log( 'deactivate', $module_slug );
				Jetpack::deactivate_module( $module_slug );
				/* translators: %s is the name of a Jetpack module */
				WP_CLI::success( sprintf( __( '%s has been deactivated.', 'jetpack' ), $module['name'] ) );
				break;
			case 'deactivate_all':
				Jetpack::delete_active_modules();
				WP_CLI::success( __( 'All modules deactivated!', 'jetpack' ) );
				break;
			case 'toggle':
				// Will never happen, should have been handled above and changed to activate or deactivate.
				break;
		}
	}

	/**
	 * Manage Protect Settings
	 *
	 * ## OPTIONS
	 *
	 * allow: Add an IP address to an always allow list.  You can also read or clear the allow list.
	 *
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack protect allow <ip address>
	 * wp jetpack protect allow list
	 * wp jetpack protect allow clear
	 *
	 * @synopsis <allow> [<ip|ip_low-ip_high|list|clear>]
	 *
	 * @param array $args Positional args.
	 */
	public function protect( $args ) {
		$action = isset( $args[0] ) ? $args[0] : 'prompt';
		if ( ! in_array( $action, array( 'whitelist', 'allow' ), true ) ) { // Still allow "whitelist" for legacy support.
			/* translators: %s is a command like "prompt" */
			WP_CLI::error( sprintf( __( '%s is not a valid command.', 'jetpack' ), $action ) );
		}
		// Check if module is active.
		if ( ! Jetpack::is_module_active( __FUNCTION__ ) ) {
			/* translators: %s is a module name */
			WP_CLI::error( sprintf( _x( '%1$s is not active. You can activate it with "wp jetpack module activate %2$s"', '"wp jetpack module activate" is a command - do not translate', 'jetpack' ), __FUNCTION__, __FUNCTION__ ) );
		}
		if ( in_array( $action, array( 'allow', 'whitelist' ), true ) ) {
			if ( isset( $args[1] ) ) {
				$action = 'allow';
			} else {
				$action = 'prompt';
			}
		}
		switch ( $action ) {
			case 'allow':
				$allow         = array();
				$new_ip        = $args[1];
				$current_allow = get_site_option( 'jetpack_protect_whitelist', array() ); // @todo Update the option name.

				// Build array of IPs that are already on the allowed list.
				// Re-build manually instead of using jetpack_protect_format_allow_list() so we can easily get
				// low & high range params for IP_Utils::ip_address_is_in_range().
				foreach ( $current_allow as $allowed ) {

					// IP ranges.
					if ( $allowed->range ) {

						// Is it already on the allowed list?
						if ( IP_Utils::ip_address_is_in_range( $new_ip, $allowed->range_low, $allowed->range_high ) ) {
							/* translators: %s is an IP address */
							WP_CLI::error( sprintf( __( '%s is already on the always allow list.', 'jetpack' ), $new_ip ) );
							break;
						}
						$allow[] = $allowed->range_low . ' - ' . $allowed->range_high;

					} else { // Individual IPs.

						// Check if the IP is already on the allow list (single IP only).
						if ( $new_ip === $allowed->ip_address ) {
							/* translators: %s is an IP address */
							WP_CLI::error( sprintf( __( '%s is already on the always allow list.', 'jetpack' ), $new_ip ) );
							break;
						}
						$allow[] = $allowed->ip_address;

					}
				}

				/*
				 * List the allowed IPs.
				 * Done here because it's easier to read the $allow array after it's been rebuilt.
				 */
				if ( isset( $args[1] ) && 'list' === $args[1] ) {
					if ( ! empty( $allow ) ) {
						WP_CLI::success( __( 'Here are your always allowed IPs:', 'jetpack' ) );
						foreach ( $allow as $ip ) {
							WP_CLI::line( "\t" . str_pad( $ip, 24 ) );
						}
					} else {
						WP_CLI::line( __( 'Always allow list is empty.', 'jetpack' ) );
					}
					break;
				}

				/*
				 * Clear the always allow list.
				 */
				if ( isset( $args[1] ) && 'clear' === $args[1] ) {
					if ( ! empty( $allow ) ) {
						$allow = array();
						Brute_Force_Protection_Shared_Functions::save_allow_list( $allow ); // @todo Need to update function name in the Protect module.
						WP_CLI::success( __( 'Cleared all IPs from the always allow list.', 'jetpack' ) );
					} else {
						WP_CLI::line( __( 'Always allow list is empty.', 'jetpack' ) );
					}
					break;
				}

				// Append new IP to allow array.
				array_push( $allow, $new_ip );

				// Save allow list if there are no errors.
				$result = Brute_Force_Protection_Shared_Functions::save_allow_list( $allow ); // @todo Need to update function name in the Protect module.
				if ( is_wp_error( $result ) ) {
					WP_CLI::error( $result );
				}

				/* translators: %s is an IP address */
				WP_CLI::success( sprintf( __( '%s has been added to the always allowed list.', 'jetpack' ), $new_ip ) );
				break;
			case 'prompt':
				WP_CLI::error(
					__( 'No command found.', 'jetpack' ) . "\n" .
					__( 'Please enter the IP address you want to always allow.', 'jetpack' ) . "\n" .
					_x( 'You can save a range of IPs {low_range}-{high_range}. No spaces allowed. (example: 1.1.1.1-2.2.2.2)', 'Instructions on how to add IP ranges - low_range/high_range should be translated.', 'jetpack' ) . "\n" .
					_x( "You can also 'list' or 'clear' the always allowed list.", "'list' and 'clear' are commands and should not be translated", 'jetpack' ) . "\n"
				);
				break;
		}
	}

	/**
	 * Manage Jetpack Options
	 *
	 * ## OPTIONS
	 *
	 * list   : List all jetpack options and their values
	 * delete : Delete an option
	 *          - can only delete options that are white listed.
	 * update : update an option
	 *          - can only update option strings
	 * get    : get the value of an option
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack options list
	 * wp jetpack options get    <option_name>
	 * wp jetpack options delete <option_name>
	 * wp jetpack options update <option_name> [<option_value>]
	 *
	 * @synopsis <list|get|delete|update> [<option_name>] [<option_value>]
	 *
	 * @param array $args Positional args.
	 */
	public function options( $args ) {
		$action         = isset( $args[0] ) ? $args[0] : 'list';
		$safe_to_modify = Jetpack_Options::get_options_for_reset();

		// Is the option flagged as unsafe?
		$flagged = ! in_array( $args[1], $safe_to_modify, true );

		if ( ! in_array( $action, array( 'list', 'get', 'delete', 'update' ), true ) ) {
			/* translators: %s is a command like "prompt" */
			WP_CLI::error( sprintf( __( '%s is not a valid command.', 'jetpack' ), $action ) );
		}

		if ( isset( $args[0] ) ) {
			if ( 'get' === $args[0] && isset( $args[1] ) ) {
				$action = 'get';
			} elseif ( 'delete' === $args[0] && isset( $args[1] ) ) {
				$action = 'delete';
			} elseif ( 'update' === $args[0] && isset( $args[1] ) ) {
				$action = 'update';
			} else {
				$action = 'list';
			}
		}

		// Bail if the option isn't found.
		$option = isset( $args[1] ) ? Jetpack_Options::get_option( $args[1] ) : false;
		if ( isset( $args[1] ) && ! $option && 'update' !== $args[0] ) {
			WP_CLI::error( __( 'Option not found or is empty. Use "list" to list option names', 'jetpack' ) );
		}

		// Let's print_r the option if it's an array.
		// Used in the 'get' and 'list' actions.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r
		$option = is_array( $option ) ? print_r( $option, true ) : $option;

		switch ( $action ) {
			case 'get':
				WP_CLI::success( "\t" . $option );
				break;
			case 'delete':
				jetpack_cli_are_you_sure( $flagged );

				Jetpack_Options::delete_option( $args[1] );
				/* translators: %s is the option name */
				WP_CLI::success( sprintf( __( 'Deleted option: %s', 'jetpack' ), $args[1] ) );
				break;
			case 'update':
				jetpack_cli_are_you_sure( $flagged );

				// Updating arrays would get pretty tricky...
				$value = Jetpack_Options::get_option( $args[1] );
				if ( $value && is_array( $value ) ) {
					WP_CLI::error( __( 'Sorry, no updating arrays at this time', 'jetpack' ) );
				}

				Jetpack_Options::update_option( $args[1], $args[2] );
				/* translators: %1$s is the previous value, %2$s is the new value */
				WP_CLI::success( sprintf( _x( 'Updated option: %1$s to "%2$s"', 'Updating an option from "this" to "that".', 'jetpack' ), $args[1], $args[2] ) );
				break;
			case 'list':
				$options_compact     = Jetpack_Options::get_option_names();
				$options_non_compact = Jetpack_Options::get_option_names( 'non_compact' );
				$options_private     = Jetpack_Options::get_option_names( 'private' );
				$options             = array_merge( $options_compact, $options_non_compact, $options_private );

				// Table headers.
				WP_CLI::line( "\t" . str_pad( __( 'Option', 'jetpack' ), 30 ) . __( 'Value', 'jetpack' ) );

				// List out the options and their values.
				// Tell them if the value is empty or not.
				// Tell them if it's an array.
				foreach ( $options as $option ) {
					$value = Jetpack_Options::get_option( $option );
					if ( ! $value ) {
						WP_CLI::line( "\t" . str_pad( $option, 30 ) . 'Empty' );
						continue;
					}

					if ( ! is_array( $value ) ) {
						WP_CLI::line( "\t" . str_pad( $option, 30 ) . $value );
					} elseif ( is_array( $value ) ) {
						WP_CLI::line( "\t" . str_pad( $option, 30 ) . 'Array - Use "get <option>" to read option array.' );
					}
				}
				$option_text = '{' . _x( 'option', 'a variable command that a user can write, provided in the printed instructions', 'jetpack' ) . '}';
				$value_text  = '{' . _x( 'value', 'the value that they want to update the option to', 'jetpack' ) . '}';

				WP_CLI::success(
					_x( "Above are your options. You may 'get', 'delete', and 'update' them.", "'get', 'delete', and 'update' are commands - do not translate.", 'jetpack' ) . "\n" .
					str_pad( 'wp jetpack options get', 26 ) . $option_text . "\n" .
					str_pad( 'wp jetpack options delete', 26 ) . $option_text . "\n" .
					str_pad( 'wp jetpack options update', 26 ) . "$option_text $value_text\n" .
					_x( "Type 'wp jetpack options' for more info.", "'wp jetpack options' is a command - do not translate.", 'jetpack' ) . "\n"
				);
				break;
		}
	}

	/**
	 * Get the status of or start a new Jetpack sync.
	 *
	 * ## OPTIONS
	 *
	 * status   : Print the current sync status
	 * settings : Prints the current sync settings
	 * start    : Start a full sync from this site to WordPress.com
	 * enable   : Enables sync on the site
	 * disable  : Disable sync on a site
	 * reset    : Disables sync and Resets the sync queues on a site
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack sync status
	 * wp jetpack sync settings
	 * wp jetpack sync start --modules=functions --sync_wait_time=5
	 * wp jetpack sync enable
	 * wp jetpack sync disable
	 * wp jetpack sync reset
	 * wp jetpack sync reset --queue=full or regular
	 *
	 * @synopsis <status|start> [--<field>=<value>]
	 *
	 * @param array $args Positional args.
	 * @param array $assoc_args Named args.
	 */
	public function sync( $args, $assoc_args ) {

		$action = isset( $args[0] ) ? $args[0] : 'status';

		switch ( $action ) {
			case 'status':
				$status     = Actions::get_sync_status();
				$collection = array();
				foreach ( $status as $key => $item ) {
					$collection[] = array(
						'option' => $key,
						'value'  => is_scalar( $item ) ? $item : wp_json_encode( $item ),
					);
				}
				WP_CLI::log( __( 'Sync Status:', 'jetpack' ) );
				WP_CLI\Utils\format_items( 'table', $collection, array( 'option', 'value' ) );
				break;
			case 'settings':
				WP_CLI::log( __( 'Sync Settings:', 'jetpack' ) );
				$settings = array();
				foreach ( Settings::get_settings() as $setting => $item ) {
					$settings[] = array(
						'setting' => $setting,
						'value'   => is_scalar( $item ) ? $item : wp_json_encode( $item ),
					);
				}
				WP_CLI\Utils\format_items( 'table', $settings, array( 'setting', 'value' ) );
				break;
			case 'disable':
				// Don't set it via the Settings since that also resets the queues.
				update_option( 'jetpack_sync_settings_disable', 1 );
				/* translators: %s is the site URL */
				WP_CLI::log( sprintf( __( 'Sync Disabled on %s', 'jetpack' ), get_site_url() ) );
				break;
			case 'enable':
				Settings::update_settings( array( 'disable' => 0 ) );
				/* translators: %s is the site URL */
				WP_CLI::log( sprintf( __( 'Sync Enabled on %s', 'jetpack' ), get_site_url() ) );
				break;
			case 'reset':
				// Don't set it via the Settings since that also resets the queues.
				update_option( 'jetpack_sync_settings_disable', 1 );

				/* translators: %s is the site URL */
				WP_CLI::log( sprintf( __( 'Sync Disabled on %s. Use `wp jetpack sync enable` to enable syncing again.', 'jetpack' ), get_site_url() ) );
				$listener = Listener::get_instance();
				if ( empty( $assoc_args['queue'] ) ) {
					$listener->get_sync_queue()->reset();
					$listener->get_full_sync_queue()->reset();
					/* translators: %s is the site URL */
					WP_CLI::log( sprintf( __( 'Reset Full Sync and Regular Queues Queue on %s', 'jetpack' ), get_site_url() ) );
					break;
				}

				if ( ! empty( $assoc_args['queue'] ) ) {
					switch ( $assoc_args['queue'] ) {
						case 'regular':
							$listener->get_sync_queue()->reset();
							/* translators: %s is the site URL */
							WP_CLI::log( sprintf( __( 'Reset Regular Sync Queue on %s', 'jetpack' ), get_site_url() ) );
							break;
						case 'full':
							$listener->get_full_sync_queue()->reset();
							/* translators: %s is the site URL */
							WP_CLI::log( sprintf( __( 'Reset Full Sync Queue on %s', 'jetpack' ), get_site_url() ) );
							break;
						default:
							WP_CLI::error( __( 'Please specify what type of queue do you want to reset: `full` or `regular`.', 'jetpack' ) );
							break;
					}
				}

				break;
			case 'start':
				if ( ! Actions::sync_allowed() ) {
					if ( Settings::get_setting( 'disable' ) ) {
						WP_CLI::error( __( 'Jetpack sync is not currently allowed for this site. It is currently disabled. Run `wp jetpack sync enable` to enable it.', 'jetpack' ) );
						return;
					}
					$connection = new Connection_Manager();
					if ( ! $connection->is_connected() ) {
						if ( ! doing_action( 'jetpack_site_registered' ) ) {
							WP_CLI::error( __( 'Jetpack sync is not currently allowed for this site. Jetpack is not connected.', 'jetpack' ) );
							return;
						}
					}

					$status = new Status();

					if ( $status->is_offline_mode() ) {
						WP_CLI::error( __( 'Jetpack sync is not currently allowed for this site. The site is in offline mode.', 'jetpack' ) );
						return;
					}
					if ( $status->is_staging_site() ) {
						WP_CLI::error( __( 'Jetpack sync is not currently allowed for this site. The site is in staging mode.', 'jetpack' ) );
						return;
					}
				}
				// Get the original settings so that we can restore them later.
				$original_settings = Settings::get_settings();

				// Initialize sync settigns so we can sync as quickly as possible.
				$sync_settings = wp_parse_args(
					array_intersect_key( $assoc_args, Settings::$valid_settings ),
					array(
						'sync_wait_time'           => 0,
						'enqueue_wait_time'        => 0,
						'queue_max_writes_sec'     => 10000,
						'max_queue_size_full_sync' => 100000,
						'full_sync_send_duration'  => HOUR_IN_SECONDS,
					)
				);
				Settings::update_settings( $sync_settings );

				// Convert comma-delimited string of modules to an array.
				if ( ! empty( $assoc_args['modules'] ) ) {
					$modules = array_map( 'trim', explode( ',', $assoc_args['modules'] ) );

					// Convert the array so that the keys are the module name and the value is true to indicate
					// that we want to sync the module.
					$modules = array_map( '__return_true', array_flip( $modules ) );
				}

				foreach ( array( 'posts', 'comments', 'users' ) as $module_name ) {
					if (
						'users' === $module_name &&
						isset( $assoc_args[ $module_name ] ) &&
						'initial' === $assoc_args[ $module_name ]
					) {
						$modules['users'] = 'initial';
					} elseif ( isset( $assoc_args[ $module_name ] ) ) {
						$ids = explode( ',', $assoc_args[ $module_name ] );
						if ( count( $ids ) > 0 ) {
							$modules[ $module_name ] = $ids;
						}
					}
				}

				if ( empty( $modules ) ) {
					$modules = null;
				}

				// Kick off a full sync.
				if ( Actions::do_full_sync( $modules ) ) {
					if ( $modules ) {
						/* translators: %s is a comma separated list of Jetpack modules */
						WP_CLI::log( sprintf( __( 'Initialized a new full sync with modules: %s', 'jetpack' ), join( ', ', array_keys( $modules ) ) ) );
					} else {
						WP_CLI::log( __( 'Initialized a new full sync', 'jetpack' ) );
					}
				} else {

					// Reset sync settings to original.
					Settings::update_settings( $original_settings );

					if ( $modules ) {
						/* translators: %s is a comma separated list of Jetpack modules */
						WP_CLI::error( sprintf( __( 'Could not start a new full sync with modules: %s', 'jetpack' ), join( ', ', $modules ) ) );
					} else {
						WP_CLI::error( __( 'Could not start a new full sync', 'jetpack' ) );
					}
				}

				// Keep sending to WPCOM until there's nothing to send.
				$i = 1;
				do {
					$result = Actions::$sender->do_full_sync();
					if ( is_wp_error( $result ) ) {
						$queue_empty_error = ( 'empty_queue_full_sync' === $result->get_error_code() );
						if ( ! $queue_empty_error || ( $queue_empty_error && ( 1 === $i ) ) ) {
							/* translators: %s is an error code  */
							WP_CLI::error( sprintf( __( 'Sync errored with code: %s', 'jetpack' ), $result->get_error_code() ) );
						}
					} else {
						if ( 1 === $i ) {
							WP_CLI::log( __( 'Sent data to WordPress.com', 'jetpack' ) );
						} else {
							WP_CLI::log( __( 'Sent more data to WordPress.com', 'jetpack' ) );
						}

						// Immediate Full Sync does not wait for WP.com to process data so we need to enforce a wait.
						if ( false !== strpos( get_class( Modules::get_module( 'full-sync' ) ), 'Full_Sync_Immediately' ) ) {
							sleep( 15 );
						}
					}
					++$i;
				} while ( $result && ! is_wp_error( $result ) );

				// Reset sync settings to original.
				Settings::update_settings( $original_settings );

				WP_CLI::success( __( 'Finished syncing to WordPress.com', 'jetpack' ) );
				break;
		}
	}

	/**
	 * List the contents of a specific Jetpack sync queue.
	 *
	 * ## OPTIONS
	 *
	 * peek : List the 100 front-most items on the queue.
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack sync_queue full_sync peek
	 *
	 * @synopsis <incremental|full_sync> <peek>
	 *
	 * @param array $args Positional args.
	 */
	public function sync_queue( $args ) {
		if ( ! Actions::sync_allowed() ) {
			WP_CLI::error( __( 'Jetpack sync is not currently allowed for this site.', 'jetpack' ) );
		}

		$queue_name = isset( $args[0] ) ? $args[0] : 'sync';
		$action     = isset( $args[1] ) ? $args[1] : 'peek';

		// We map the queue name that way we can support more friendly queue names in the commands, but still use
		// the queue name that the code expects.
		$allowed_queues    = array(
			'incremental' => 'sync',
			'full'        => 'full_sync',
		);
		$queue_name_map    = $allowed_queues;
		$mapped_queue_name = isset( $queue_name_map[ $queue_name ] ) ? $queue_name_map[ $queue_name ] : $queue_name;

		switch ( $action ) {
			case 'peek':
				$queue = new Queue( $mapped_queue_name );
				$items = $queue->peek( 100 );

				if ( empty( $items ) ) {
					/* translators: %s is the name of the queue, either 'incremental' or 'full' */
					WP_CLI::log( sprintf( __( 'Nothing is in the queue: %s', 'jetpack' ), $queue_name ) );
				} else {
					$collection = array();
					foreach ( $items as $item ) {
						$collection[] = array(
							'action'          => $item[0],
							'args'            => wp_json_encode( $item[1] ),
							'current_user_id' => $item[2],
							'microtime'       => $item[3],
							'importing'       => (string) $item[4],
						);
					}
					WP_CLI\Utils\format_items(
						'table',
						$collection,
						array(
							'action',
							'args',
							'current_user_id',
							'microtime',
							'importing',
						)
					);
				}
				break;
		}
	}

	/**
	 * Cancel's the current Jetpack plan granted by this partner, if applicable
	 *
	 * Returns success or error JSON
	 *
	 * <token_json>
	 * : JSON blob of WPCOM API token
	 *  [--partner_tracking_id=<partner_tracking_id>]
	 * : This is an optional ID that a host can pass to help identify a site in logs on WordPress.com
	 *
	 * @synopsis <token_json> [--partner_tracking_id=<partner_tracking_id>]
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function partner_cancel( $args, $named_args ) {
		list( $token_json ) = $args;

		$token = $token_json ? json_decode( $token_json ) : null;
		if ( ! $token ) {
			/* translators: %s is the invalid JSON string */
			$this->partner_provision_error( new WP_Error( 'missing_access_token', sprintf( __( 'Invalid token JSON: %s', 'jetpack' ), $token_json ) ) );
		}

		if ( isset( $token->error ) ) {
			$this->partner_provision_error( new WP_Error( $token->error, $token->message ) );
		}

		if ( ! isset( $token->access_token ) ) {
			$this->partner_provision_error( new WP_Error( 'missing_access_token', __( 'Missing or invalid access token', 'jetpack' ) ) );
		}

		if ( Identity_Crisis::validate_sync_error_idc_option() ) {
			$this->partner_provision_error(
				new WP_Error(
					'site_in_safe_mode',
					esc_html__( 'Can not cancel a plan while in safe mode. See: https://jetpack.com/support/safe-mode/', 'jetpack' )
				)
			);
		}

		$site_identifier = Jetpack_Options::get_option( 'id' );

		if ( ! $site_identifier ) {
			$status          = new Status();
			$site_identifier = $status->get_site_suffix();
		}

		$request = array(
			'headers' => array(
				'Authorization' => 'Bearer ' . $token->access_token,
				'Host'          => 'public-api.wordpress.com',
			),
			'timeout' => 60,
			'method'  => 'POST',
		);

		$url = sprintf( '%s/rest/v1.3/jpphp/%s/partner-cancel', $this->get_api_host(), $site_identifier );
		if ( ! empty( $named_args ) && ! empty( $named_args['partner_tracking_id'] ) ) {
			$url = esc_url_raw( add_query_arg( 'partner_tracking_id', $named_args['partner_tracking_id'], $url ) );
		}

		$result = Client::_wp_remote_request( $url, $request );

		Jetpack_Options::delete_option( 'onboarding' );

		if ( is_wp_error( $result ) ) {
			$this->partner_provision_error( $result );
		}

		WP_CLI::log( wp_remote_retrieve_body( $result ) );
	}

	/**
	 * Provision a site using a Jetpack Partner license
	 *
	 * Returns JSON blob
	 *
	 * ## OPTIONS
	 *
	 * <token_json>
	 * : JSON blob of WPCOM API token
	 * [--plan=<plan_name>]
	 * : Slug of the requested plan, e.g. premium
	 * [--wpcom_user_id=<user_id>]
	 * : WordPress.com ID of user to connect as (must be whitelisted against partner key)
	 * [--wpcom_user_email=<wpcom_user_email>]
	 * : Override the email we send to WordPress.com for registration
	 * [--onboarding=<onboarding>]
	 * : Guide the user through an onboarding wizard
	 * [--force_register=<register>]
	 * : Whether to force a site to register
	 * [--force_connect=<force_connect>]
	 * : Force JPS to not reuse existing credentials
	 * [--home_url=<home_url>]
	 * : Overrides the home option via the home_url filter, or the WP_HOME constant
	 * [--site_url=<site_url>]
	 * : Overrides the siteurl option via the site_url filter, or the WP_SITEURL constant
	 * [--partner_tracking_id=<partner_tracking_id>]
	 * : This is an optional ID that a host can pass to help identify a site in logs on WordPress.com
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp jetpack partner_provision '{ some: "json" }' premium 1
	 *     { success: true }
	 *
	 * @synopsis <token_json> [--wpcom_user_id=<user_id>] [--plan=<plan_name>] [--onboarding=<onboarding>] [--force_register=<register>] [--force_connect=<force_connect>] [--home_url=<home_url>] [--site_url=<site_url>] [--wpcom_user_email=<wpcom_user_email>] [--partner_tracking_id=<partner_tracking_id>]
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function partner_provision( $args, $named_args ) {
		list( $token_json ) = $args;

		$token = $token_json ? json_decode( $token_json ) : null;
		if ( ! $token ) {
			/* translators: %s is the invalid JSON string */
			$this->partner_provision_error( new WP_Error( 'missing_access_token', sprintf( __( 'Invalid token JSON: %s', 'jetpack' ), $token_json ) ) );
		}

		if ( isset( $token->error ) ) {
			$message = isset( $token->message )
				? $token->message
				: '';
			$this->partner_provision_error( new WP_Error( $token->error, $message ) );
		}

		if ( ! isset( $token->access_token ) ) {
			$this->partner_provision_error( new WP_Error( 'missing_access_token', __( 'Missing or invalid access token', 'jetpack' ) ) );
		}

		require_once JETPACK__PLUGIN_DIR . '_inc/class.jetpack-provision.php';

		$body_json = Jetpack_Provision::partner_provision( $token->access_token, $named_args );

		if ( is_wp_error( $body_json ) ) {
			WP_CLI::error(
				wp_json_encode(
					array(
						'success'       => false,
						'error_code'    => $body_json->get_error_code(),
						'error_message' => $body_json->get_error_message(),
					)
				)
			);
			exit( 1 );
		}

		WP_CLI::log( wp_json_encode( $body_json ) );
	}

	/**
	 * Manages your Jetpack sitemap
	 *
	 * ## OPTIONS
	 *
	 * rebuild : Rebuild all sitemaps
	 * --purge : if set, will remove all existing sitemap data before rebuilding
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack sitemap rebuild
	 *
	 * @subcommand sitemap
	 * @synopsis <rebuild> [--purge]
	 *
	 * @param array $args Positional args.
	 * @param array $assoc_args Named args.
	 */
	public function sitemap( $args, $assoc_args ) {
		if ( ! Jetpack::is_connection_ready() ) {
			WP_CLI::error( __( 'Jetpack is not currently connected to WordPress.com', 'jetpack' ) );
		}
		if ( ! Jetpack::is_module_active( 'sitemaps' ) ) {
			WP_CLI::error( __( 'Jetpack Sitemaps module is not currently active. Activate it first if you want to work with sitemaps.', 'jetpack' ) );
		}
		if ( ! class_exists( 'Jetpack_Sitemap_Builder' ) ) {
			WP_CLI::error( __( 'Jetpack Sitemaps module is active, but unavailable. This can happen if your site is set to discourage search engine indexing. Please enable search engine indexing to allow sitemap generation.', 'jetpack' ) );
		}

		if ( isset( $assoc_args['purge'] ) && $assoc_args['purge'] ) {
			$librarian = new Jetpack_Sitemap_Librarian();
			$librarian->delete_all_stored_sitemap_data();
		}

		$sitemap_builder = new Jetpack_Sitemap_Builder();
		$sitemap_builder->update_sitemap();
	}

	/**
	 * Allows authorizing a user via the command line and will activate
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack authorize_user --token=123456789abcdef
	 *
	 * @synopsis --token=<value>
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function authorize_user( $args, $named_args ) {
		if ( ! is_user_logged_in() ) {
			WP_CLI::error( __( 'Please select a user to authorize via the --user global argument.', 'jetpack' ) );
		}

		if ( empty( $named_args['token'] ) ) {
			WP_CLI::error( __( 'A non-empty token argument must be passed.', 'jetpack' ) );
		}

		$is_connection_owner = ! Jetpack::connection()->has_connected_owner();
		$current_user_id     = get_current_user_id();

		( new Tokens() )->update_user_token( $current_user_id, sprintf( '%s.%d', $named_args['token'], $current_user_id ), $is_connection_owner );

		WP_CLI::log( wp_json_encode( $named_args ) );

		if ( $is_connection_owner ) {
			/**
			 * Auto-enable SSO module for new Jetpack Start connections
			*
			* @since 5.0.0
			*
			* @param bool $enable_sso Whether to enable the SSO module. Default to true.
			*/
			$enable_sso = apply_filters( 'jetpack_start_enable_sso', true );
			Jetpack::handle_post_authorization_actions( $enable_sso, false );

			/* translators: %d is a user ID */
			WP_CLI::success( sprintf( __( 'Authorized %d and activated default modules.', 'jetpack' ), $current_user_id ) );
		} else {
			/* translators: %d is a user ID */
			WP_CLI::success( sprintf( __( 'Authorized %d.', 'jetpack' ), $current_user_id ) );
		}
	}

	/**
	 * Allows calling a WordPress.com API endpoint using the current blog's token.
	 *
	 * ## OPTIONS
	 * --resource=<resource>
	 * : The resource to call with the current blog's token, where `%d` represents the current blog's ID.
	 *
	 * [--api_version=<api_version>]
	 * : The API version to query against.
	 *
	 * [--base_api_path=<base_api_path>]
	 * : The base API path to query.
	 * ---
	 * default: rest
	 * ---
	 *
	 * [--body=<body>]
	 * : A JSON encoded string representing arguments to send in the body.
	 *
	 * [--field=<value>]
	 * : Any number of arguments that should be passed to the resource.
	 *
	 * [--pretty]
	 * : Will pretty print the results of a successful API call.
	 *
	 * [--strip-success]
	 * : Will remove the green success label from successful API calls.
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack call_api --resource='/sites/%d'
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function call_api( $args, $named_args ) {
		if ( ! Jetpack::is_connection_ready() ) {
			WP_CLI::error( __( 'Jetpack is not currently connected to WordPress.com', 'jetpack' ) );
		}

		$consumed_args = array(
			'resource',
			'api_version',
			'base_api_path',
			'body',
			'pretty',
		);

		// Get args that should be passed to resource.
		$other_args = array_diff_key( $named_args, array_flip( $consumed_args ) );

		$decoded_body = ! empty( $named_args['body'] )
			? json_decode( $named_args['body'], true )
			: false;

		$resource_url = ( false === strpos( $named_args['resource'], '%d' ) )
			? $named_args['resource']
			: sprintf( $named_args['resource'], Jetpack_Options::get_option( 'id' ) );

		$response = Client::wpcom_json_api_request_as_blog(
			$resource_url,
			empty( $named_args['api_version'] ) ? Client::WPCOM_JSON_API_VERSION : $named_args['api_version'],
			$other_args,
			empty( $decoded_body ) ? null : $decoded_body,
			empty( $named_args['base_api_path'] ) ? 'rest' : $named_args['base_api_path']
		);

		if ( is_wp_error( $response ) ) {
			WP_CLI::error(
				sprintf(
					/* translators: %1$s is an endpoint route (ex. /sites/123456), %2$d is an error code, %3$s is an error message. */
					__( 'Request to %1$s returned an error: (%2$d) %3$s.', 'jetpack' ),
					$resource_url,
					$response->get_error_code(),
					$response->get_error_message()
				)
			);
		}

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			WP_CLI::error(
				sprintf(
					/* translators: %1$s is an endpoint route (ex. /sites/123456), %2$d is an HTTP status code. */
					__( 'Request to %1$s returned a non-200 response code: %2$d.', 'jetpack' ),
					$resource_url,
					wp_remote_retrieve_response_code( $response )
				)
			);
		}

		$output = wp_remote_retrieve_body( $response );
		if ( isset( $named_args['pretty'] ) ) {
			$decoded_output = json_decode( $output );
			if ( $decoded_output ) {
				$output = wp_json_encode( $decoded_output, JSON_PRETTY_PRINT );
			}
		}

		if ( isset( $named_args['strip-success'] ) ) {
			WP_CLI::log( $output );
			WP_CLI::halt( 0 );
		}

		WP_CLI::success( $output );
	}

	/**
	 * Allows uploading SSH Credentials to the current site for backups, restores, and security scanning.
	 *
	 * ## OPTIONS
	 *
	 * [--host=<host>]
	 * : The SSH server's address.
	 *
	 * [--ssh-user=<user>]
	 * : The username to use to log in to the SSH server.
	 *
	 * [--pass=<pass>]
	 * : The password used to log in, if using a password. (optional)
	 *
	 * [--kpri=<kpri>]
	 * : The private key used to log in, if using a private key. (optional)
	 *
	 * [--pretty]
	 * : Will pretty print the results of a successful API call. (optional)
	 *
	 * [--strip-success]
	 * : Will remove the green success label from successful API calls. (optional)
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack upload_ssh_creds --host=example.com --ssh-user=example --pass=password
	 * wp jetpack updload_ssh_creds --host=example.com --ssh-user=example --kpri=key
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function upload_ssh_creds( $args, $named_args ) {
		if ( ! Jetpack::is_connection_ready() ) {
			WP_CLI::error( __( 'Jetpack is not currently connected to WordPress.com', 'jetpack' ) );
		}

		$required_args = array(
			'host',
			'ssh-user',
		);

		foreach ( $required_args as $arg ) {
			if ( empty( $named_args[ $arg ] ) ) {
				WP_CLI::error(
					sprintf(
						/* translators: %s is a slug, such as 'host'. */
						__( '`%s` cannot be empty.', 'jetpack' ),
						$arg
					)
				);
			}
		}

		if ( empty( $named_args['pass'] ) && empty( $named_args['kpri'] ) ) {
			WP_CLI::error( __( 'Both `pass` and `kpri` fields cannot be blank.', 'jetpack' ) );
		}

		$values = array(
			'credentials' => array(
				'site_url' => get_site_url(),
				'abspath'  => ABSPATH,
				'protocol' => 'ssh',
				'port'     => 22,
				'role'     => 'main',
				'host'     => $named_args['host'],
				'user'     => $named_args['ssh-user'],
				'pass'     => empty( $named_args['pass'] ) ? '' : $named_args['pass'],
				'kpri'     => empty( $named_args['kpri'] ) ? '' : $named_args['kpri'],
			),
		);

		$named_args = wp_parse_args(
			array(
				'resource'    => '/activity-log/%d/update-credentials',
				'method'      => 'POST',
				'api_version' => '1.1',
				'body'        => wp_json_encode( $values ),
				'timeout'     => 30,
			),
			$named_args
		);

		self::call_api( $args, $named_args );
	}

	/**
	 * API wrapper for getting stats from the WordPress.com API for the current site.
	 *
	 * ## OPTIONS
	 *
	 * [--quantity=<quantity>]
	 * : The number of units to include.
	 * ---
	 * default: 30
	 * ---
	 *
	 * [--period=<period>]
	 * : The unit of time to query stats for.
	 * ---
	 * default: day
	 * options:
	 *  - day
	 *  - week
	 *  - month
	 *  - year
	 * ---
	 *
	 * [--date=<date>]
	 * : The latest date to return stats for. Ex. - 2018-01-01.
	 *
	 * [--pretty]
	 * : Will pretty print the results of a successful API call.
	 *
	 * [--strip-success]
	 * : Will remove the green success label from successful API calls.
	 *
	 * ## EXAMPLES
	 *
	 * wp jetpack get_stats
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function get_stats( $args, $named_args ) {
		$selected_args = array_intersect_key(
			$named_args,
			array_flip(
				array(
					'quantity',
					'date',
				)
			)
		);

		// The API expects unit, but period seems to be more correct.
		$selected_args['unit'] = $named_args['period'];

		$command = sprintf(
			'jetpack call_api --resource=/sites/%d/stats/%s',
			Jetpack_Options::get_option( 'id' ),
			add_query_arg( $selected_args, 'visits' )
		);

		if ( isset( $named_args['pretty'] ) ) {
			$command .= ' --pretty';
		}

		if ( isset( $named_args['strip-success'] ) ) {
			$command .= ' --strip-success';
		}

		WP_CLI::runcommand(
			$command,
			array(
				'launch' => false, // Use the current process.
			)
		);
	}

	/**
	 * Allows management of publicize connections.
	 *
	 * ## OPTIONS
	 *
	 * <list|disconnect>
	 * : The action to perform.
	 * ---
	 * options:
	 *   - list
	 *   - disconnect
	 * ---
	 *
	 * [<identifier>]
	 * : The connection ID or service to perform an action on.
	 *
	 * [--format=<format>]
	 * : Allows overriding the output of the command when listing connections.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 *   - ids
	 *   - count
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # List all publicize connections.
	 *     $ wp jetpack publicize list
	 *
	 *     # List publicize connections for a given service.
	 *     $ wp jetpack publicize list twitter
	 *
	 *     # List all publicize connections for a given user.
	 *     $ wp --user=1 jetpack publicize list
	 *
	 *     # List all publicize connections for a given user and service.
	 *     $ wp --user=1 jetpack publicize list twitter
	 *
	 *     # Display details for a given connection.
	 *     $ wp jetpack publicize list 123456
	 *
	 *     # Diconnection a given connection.
	 *     $ wp jetpack publicize disconnect 123456
	 *
	 *     # Disconnect all connections.
	 *     $ wp jetpack publicize disconnect all
	 *
	 *     # Disconnect all connections for a given service.
	 *     $ wp jetpack publicize disconnect twitter
	 *
	 * @param array $args Positional args.
	 * @param array $named_args Named args.
	 */
	public function publicize( $args, $named_args ) {
		if ( ! Jetpack::connection()->has_connected_owner() ) {
			WP_CLI::error( __( 'Jetpack Social requires a user-level connection to WordPress.com', 'jetpack' ) );
		}

		if ( ! Jetpack::is_module_active( 'publicize' ) ) {
			WP_CLI::error( __( 'The Jetpack Social module is not active.', 'jetpack' ) );
		}

		if ( ( new Status() )->is_offline_mode() ) {
			if (
				! defined( 'JETPACK_DEV_DEBUG' ) &&
				! has_filter( 'jetpack_development_mode' ) &&
				! has_filter( 'jetpack_offline_mode' ) &&
				false === strpos( site_url(), '.' )
			) {
				WP_CLI::error( __( "Jetpack is current in offline mode because the site url does not contain a '.', which often occurs when dynamically setting the WP_SITEURL constant. While in offline mode, the Jetpack Social module will not load.", 'jetpack' ) );
			}

			WP_CLI::error( __( 'Jetpack is currently in offline mode, so the Jetpack Social module will not load.', 'jetpack' ) );
		}

		if ( ! class_exists( 'Publicize' ) ) {
			WP_CLI::error( __( 'The Jetpack Social module is not loaded.', 'jetpack' ) );
		}

		$action        = $args[0];
		$publicize     = new Publicize();
		$identifier    = ! empty( $args[1] ) ? $args[1] : false;
		$services      = array_keys( $publicize->get_services() );
		$id_is_service = in_array( $identifier, $services, true );

		switch ( $action ) {
			case 'list':
				$connections_to_return = array();

				// For the CLI command, let's return all connections when a user isn't specified. This
				// differs from the logic in the Publicize class.
				$option_connections = is_user_logged_in()
					? (array) $publicize->get_all_connections_for_user()
					: (array) $publicize->get_all_connections();

				foreach ( $option_connections as $service_name => $connections ) {
					foreach ( (array) $connections as $id => $connection ) {
						$connection['id']        = $id;
						$connection['service']   = $service_name;
						$connections_to_return[] = $connection;
					}
				}

				if ( $id_is_service && ! empty( $identifier ) && ! empty( $connections_to_return ) ) {
					$temp_connections      = $connections_to_return;
					$connections_to_return = array();

					foreach ( $temp_connections as $connection ) {
						if ( $identifier === $connection['service'] ) {
							$connections_to_return[] = $connection;
						}
					}
				}

				if ( $identifier && ! $id_is_service && ! empty( $connections_to_return ) ) {
					$connections_to_return = wp_list_filter( $connections_to_return, array( 'id' => $identifier ) );
				}

				$expected_keys = array(
					'id',
					'service',
					'user_id',
					'provider',
					'issued',
					'expires',
					'external_id',
					'external_name',
					'external_display',
					'type',
					'connection_data',
				);

				// Somehow, a test site ended up in a state where $connections_to_return looked like:
				// array( array( array( 'id' => 0, 'service' => 0 ) ) ) // phpcs:ignore Squiz.PHP.CommentedOutCode.Found
				// This caused the CLI command to error when running WP_CLI\Utils\format_items() below. So
				// to minimize future issues, this nested loop will remove any connections that don't contain
				// any keys that we expect.
				foreach ( (array) $connections_to_return as $connection_key => $connection ) {
					foreach ( $expected_keys as $expected_key ) {
						if ( ! isset( $connection[ $expected_key ] ) ) {
							unset( $connections_to_return[ $connection_key ] );
							continue;
						}
					}
				}

				if ( empty( $connections_to_return ) ) {
					return false;
				}

				WP_CLI\Utils\format_items( $named_args['format'], $connections_to_return, $expected_keys );
				break; // list.
			case 'disconnect':
				if ( ! $identifier ) {
					WP_CLI::error( __( 'A connection ID must be passed in order to disconnect.', 'jetpack' ) );
				}

				// If the connection ID is 'all' then delete all connections. If the connection ID
				// matches a service, delete all connections for that service.
				if ( 'all' === $identifier || $id_is_service ) {
					if ( 'all' === $identifier ) {
						WP_CLI::log( __( "You're about to delete all Jetpack Social connections.", 'jetpack' ) );
					} else {
						/* translators: %s is a lowercase string for a social network. */
						WP_CLI::log( sprintf( __( "You're about to delete all Jetpack Social connections to %s.", 'jetpack' ), $identifier ) );
					}

					jetpack_cli_are_you_sure();

					$connections = array();
					$service     = $identifier;

					$option_connections = is_user_logged_in()
						? (array) $publicize->get_all_connections_for_user()
						: (array) $publicize->get_all_connections();

					if ( 'all' === $service ) {
						foreach ( (array) $option_connections as $service_name => $service_connections ) {
							foreach ( $service_connections as $id => $connection ) {
								$connections[ $id ] = $connection;
							}
						}
					} elseif ( ! empty( $option_connections[ $service ] ) ) {
						$connections = $option_connections[ $service ];
					}

					if ( ! empty( $connections ) ) {
						$count    = count( $connections );
						$progress = \WP_CLI\Utils\make_progress_bar(
							/* translators: %s is a lowercase string for a social network. */
							sprintf( __( 'Disconnecting all connections to %s.', 'jetpack' ), $service ),
							$count
						);

						foreach ( $connections as $id => $connection ) {
							if ( false === $publicize->disconnect( false, $id ) ) {
								WP_CLI::error(
									sprintf(
										/* translators: %1$d is a numeric ID and %2$s is a lowercase string for a social network. */
										__( 'Jetpack Social connection %d could not be disconnected', 'jetpack' ),
										$id
									)
								);
							}

							$progress->tick();
						}

						$progress->finish();

						if ( 'all' === $service ) {
							WP_CLI::success( __( 'All Jetpack Social connections were successfully disconnected.', 'jetpack' ) );
						} else {
							/* translators: %s is a lowercase string for a social network. */
							WP_CLI::success( __( 'All Jetpack Social connections to %s were successfully disconnected.', 'jetpack' ), $service );
						}
					}
				} elseif ( false !== $publicize->disconnect( false, $identifier ) ) {
					/* translators: %d is a numeric ID. Example: 1234. */
					WP_CLI::success( sprintf( __( 'Jetpack Social connection %d has been disconnected.', 'jetpack' ), $identifier ) );
				} else {
					/* translators: %d is a numeric ID. Example: 1234. */
					WP_CLI::error( sprintf( __( 'Jetpack Social connection %d could not be disconnected.', 'jetpack' ), $identifier ) );
				}
				break; // disconnect.
		}
	}

	/**
	 * Get the API host.
	 *
	 * @return string URL.
	 */
	private function get_api_host() {
		$env_api_host = getenv( 'JETPACK_START_API_HOST', true );
		return $env_api_host ? 'https://' . $env_api_host : JETPACK__WPCOM_JSON_API_BASE;
	}

	/**
	 * Log and exit on a partner provision error.
	 *
	 * @param WP_Error $error Error.
	 */
	private function partner_provision_error( $error ) {
		WP_CLI::log(
			wp_json_encode(
				array(
					'success'       => false,
					'error_code'    => $error->get_error_code(),
					'error_message' => $error->get_error_message(),
				)
			)
		);
		exit( 1 );
	}

	/**
	 * Creates the essential files in Jetpack to start building a Gutenberg block or plugin.
	 *
	 * ## TYPES
	 *
	 * block: it creates a Jetpack block. All files will be created in a directory under extensions/blocks named based on the block title or a specific given slug.
	 *
	 * ## BLOCK TYPE OPTIONS
	 *
	 * The first parameter is the block title and it's not associative. Add it wrapped in quotes.
	 * The title is also used to create the slug and the edit PHP class name. If it's something like "Logo gallery", the slug will be 'logo-gallery' and the class name will be LogoGalleryEdit.
	 * --slug: Specific slug to identify the block that overrides the one generated based on the title.
	 * --description: Allows to provide a text description of the block.
	 * --keywords: Provide up to three keywords separated by comma so users can find this block when they search in Gutenberg's inserter.
	 * --variation: Allows to decide whether the block should be a production block, experimental, or beta. Defaults to Beta when arg not provided.
	 *
	 * ## BLOCK TYPE EXAMPLES
	 *
	 * wp jetpack scaffold block "Cool Block"
	 * wp jetpack scaffold block "Amazing Rock" --slug="good-music" --description="Rock the best music on your site"
	 * wp jetpack scaffold block "Jukebox" --keywords="music, audio, media"
	 * wp jetpack scaffold block "Jukebox" --variation="experimental"
	 *
	 * @subcommand scaffold block
	 * @synopsis <type> <title> [--slug] [--description] [--keywords] [--variation]
	 *
	 * @param array $args       Positional parameters, when strings are passed, wrap them in quotes.
	 * @param array $assoc_args Associative parameters like --slug="nice-block".
	 */
	public function scaffold( $args, $assoc_args ) {
		// It's ok not to check if it's set, because otherwise WPCLI exits earlier.
		switch ( $args[0] ) {
			case 'block':
				$this->block( $args, $assoc_args );
				break;
			default:
				/* translators: %s is the subcommand */
				WP_CLI::error( sprintf( esc_html__( 'Invalid subcommand %s.', 'jetpack' ), $args[0] ) . ' 👻' );
				exit( 1 );
		}
	}

	/**
	 * Creates the essential files in Jetpack to build a Gutenberg block.
	 *
	 * @param array $args       Positional parameters. Only one is used, that corresponds to the block title.
	 * @param array $assoc_args Associative parameters defined in the scaffold() method.
	 */
	public function block( $args, $assoc_args ) {
		if ( isset( $args[1] ) ) {
			$title = ucwords( $args[1] );
		} else {
			WP_CLI::error( esc_html__( 'The title parameter is required.', 'jetpack' ) . ' 👻' );
			exit( 1 );
		}

		$slug = isset( $assoc_args['slug'] )
			? $assoc_args['slug']
			: sanitize_title( $title );

		$variation_options = array( 'production', 'experimental', 'beta' );
		$variation         = ( isset( $assoc_args['variation'] ) && in_array( $assoc_args['variation'], $variation_options, true ) )
			? $assoc_args['variation']
			: 'beta';

		if ( preg_match( '#^jetpack/#', $slug ) ) {
			$slug = preg_replace( '#^jetpack/#', '', $slug );
		}

		if ( ! preg_match( '/^[a-z][a-z0-9\-]*$/', $slug ) ) {
			WP_CLI::error( esc_html__( 'Invalid block slug. They can contain only lowercase alphanumeric characters or dashes, and start with a letter', 'jetpack' ) . ' 👻' );
		}

		global $wp_filesystem;
		if ( ! WP_Filesystem() ) {
			WP_CLI::error( esc_html__( "Can't write files", 'jetpack' ) . ' 😱' );
		}

		$path = JETPACK__PLUGIN_DIR . "extensions/blocks/$slug";

		if ( $wp_filesystem->exists( $path ) && $wp_filesystem->is_dir( $path ) ) {
			/* translators: %s is path to the conflicting block */
			WP_CLI::error( sprintf( esc_html__( 'Name conflicts with the existing block %s', 'jetpack' ), $path ) . ' ⛔️' );
			exit( 1 );
		}

		$wp_filesystem->mkdir( $path );

		$has_keywords = isset( $assoc_args['keywords'] );

		$files = array(
			"$path/$slug.php"     => $this->render_block_file(
				'block-register-php',
				array(
					'slug'             => $slug,
					'title'            => $title,
					'underscoredSlug'  => str_replace( '-', '_', $slug ),
					'underscoredTitle' => str_replace( ' ', '_', $title ),
				)
			),
			"$path/index.js"      => $this->render_block_file(
				'block-index-js',
				array(
					'slug'        => $slug,
					'title'       => $title,
					'description' => isset( $assoc_args['description'] )
						? $assoc_args['description']
						: $title,
					'keywords'    => $has_keywords
					? array_map(
						function ( $keyword ) {
								// Construction necessary for Mustache lists.
								return array( 'keyword' => trim( $keyword ) );
						},
						explode( ',', $assoc_args['keywords'], 3 )
					)
					: '',
					'hasKeywords' => $has_keywords,
				)
			),
			"$path/editor.js"     => $this->render_block_file( 'block-editor-js' ),
			"$path/editor.scss"   => $this->render_block_file(
				'block-editor-scss',
				array(
					'slug'  => $slug,
					'title' => $title,
				)
			),
			"$path/edit.js"       => $this->render_block_file(
				'block-edit-js',
				array(
					'title'     => $title,
					'className' => str_replace( ' ', '', ucwords( str_replace( '-', ' ', $slug ) ) ),
				)
			),
			"$path/icon.js"       => $this->render_block_file( 'block-icon-js' ),
			"$path/attributes.js" => $this->render_block_file( 'block-attributes-js' ),
		);

		$files_written = array();

		foreach ( $files as $filename => $contents ) {
			if ( $wp_filesystem->put_contents( $filename, $contents ) ) {
				$files_written[] = $filename;
			} else {
				/* translators: %s is a file name */
				WP_CLI::error( sprintf( esc_html__( 'Error creating %s', 'jetpack' ), $filename ) );
			}
		}

		if ( empty( $files_written ) ) {
			WP_CLI::log( esc_html__( 'No files were created', 'jetpack' ) );
		} else {
			// Load index.json and insert the slug of the new block in its block variation array.
			$block_list_path = JETPACK__PLUGIN_DIR . 'extensions/index.json';
			$block_list      = $wp_filesystem->get_contents( $block_list_path );
			if ( empty( $block_list ) ) {
				/* translators: %s is the path to the file with the block list */
				WP_CLI::error( sprintf( esc_html__( 'Error fetching contents of %s', 'jetpack' ), $block_list_path ) );
			} elseif ( false === stripos( $block_list, $slug ) ) {
				$new_block_list                   = json_decode( $block_list );
				$new_block_list->{ $variation }[] = $slug;

				// Format the JSON to match our coding standards.
				$new_block_list_formatted = wp_json_encode( $new_block_list, JSON_PRETTY_PRINT ) . "\n";
				$new_block_list_formatted = preg_replace_callback(
					// Find all occurrences of multiples of 4 spaces a the start of the line.
					'/^((?:    )+)/m',
					function ( $matches ) {
						// Replace each occurrence of 4 spaces with a tab character.
						return str_repeat( "\t", substr_count( $matches[0], '    ' ) );
					},
					$new_block_list_formatted
				);

				if ( ! $wp_filesystem->put_contents( $block_list_path, $new_block_list_formatted ) ) {
					/* translators: %s is the path to the file with the block list */
					WP_CLI::error( sprintf( esc_html__( 'Error writing new %s', 'jetpack' ), $block_list_path ) );
				}
			}

			if ( 'beta' === $variation || 'experimental' === $variation ) {
				$block_constant = sprintf(
					/* translators: the placeholder is a constant name */
					esc_html__( 'To load the block, add the constant JETPACK_BLOCKS_VARIATION set to %1$s to your wp-config.php file', 'jetpack' ),
					$variation
				);
			} else {
				$block_constant = '';
			}

			WP_CLI::success(
				sprintf(
					/* translators: the placeholders are a human readable title, and a series of words separated by dashes */
					esc_html__( 'Successfully created block %1$s with slug %2$s', 'jetpack' ) . ' 🎉' . "\n" .
					"--------------------------------------------------------------------------------------------------------------------\n" .
					/* translators: the placeholder is a directory path */
					esc_html__( 'The files were created at %3$s', 'jetpack' ) . "\n" .
					esc_html__( 'To start using the block, build the blocks with pnpm run build-extensions', 'jetpack' ) . "\n" .
					/* translators: the placeholder is a file path */
					esc_html__( 'The block slug has been added to the %4$s list at %5$s', 'jetpack' ) . "\n" .
					'%6$s' . "\n" .
					/* translators: the placeholder is a URL */
					"\n" . esc_html__( 'Read more at %7$s', 'jetpack' ) . "\n",
					$title,
					$slug,
					$path,
					$variation,
					$block_list_path,
					$block_constant,
					'https://github.com/Automattic/jetpack/blob/trunk/projects/plugins/jetpack/extensions/README.md#developing-block-editor-extensions-in-jetpack'
				) . '--------------------------------------------------------------------------------------------------------------------'
			);
		}
	}

	/**
	 * Built the file replacing the placeholders in the template with the data supplied.
	 *
	 * @param string $template Template.
	 * @param array  $data Data.
	 * @return string mixed
	 */
	private static function render_block_file( $template, $data = array() ) {
		return \WP_CLI\Utils\mustache_render( JETPACK__PLUGIN_DIR . "wp-cli-templates/$template.mustache", $data );
	}
}

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move these functions to some other file.

/**
 * Standard "ask for permission to continue" function.
 * If action cancelled, ask if they need help.
 *
 * Written outside of the class so it's not listed as an executable command w/ 'wp jetpack'
 *
 * @param bool   $flagged false = normal option | true = flagged by get_jetpack_options_for_reset().
 * @param string $error_msg Error message.
 */
function jetpack_cli_are_you_sure( $flagged = false, $error_msg = false ) {
	$cli = new Jetpack_CLI();

	// Default cancellation message.
	if ( ! $error_msg ) {
		$error_msg =
			__( 'Action cancelled. Have a question?', 'jetpack' )
			. ' '
			. $cli->green_open
			. 'jetpack.com/support'
			. $cli->color_close;
	}

	if ( ! $flagged ) {
		$prompt_message = _x( 'Are you sure? This cannot be undone. Type "yes" to continue:', '"yes" is a command - do not translate.', 'jetpack' );
	} else {
		$prompt_message = _x( 'Are you sure? Modifying this option may disrupt your Jetpack connection. Type "yes" to continue.', '"yes" is a command - do not translate.', 'jetpack' );
	}

	WP_CLI::line( $prompt_message );
	$handle = fopen( 'php://stdin', 'r' );
	$line   = fgets( $handle );
	if ( 'yes' !== trim( $line ) ) {
		WP_CLI::error( $error_msg );
	}
}
