<?php
/**
 * Jetpack Heartbeat package.
 *
 * @package  automattic/jetpack-connection
 */

namespace Automattic\Jetpack;

use Jetpack_Options;
use WP_CLI;

/**
 * Heartbeat sends a batch of stats to wp.com once a day
 */
class Heartbeat {

	/**
	 * Holds the singleton instance of this class
	 *
	 * @since 1.0.0
	 * @since-jetpack 2.3.3
	 * @var Heartbeat
	 */
	private static $instance = false;

	/**
	 * Cronjob identifier
	 *
	 * @var string
	 */
	private $cron_name = 'jetpack_v2_heartbeat';

	/**
	 * Singleton
	 *
	 * @since 1.0.0
	 * @since-jetpack 2.3.3
	 * @static
	 * @return Heartbeat
	 */
	public static function init() {
		if ( ! self::$instance ) {
			self::$instance = new Heartbeat();
		}

		return self::$instance;
	}

	/**
	 * Constructor for singleton
	 *
	 * @since 1.0.0
	 * @since-jetpack 2.3.3
	 */
	private function __construct() {

		// Schedule the task.
		add_action( $this->cron_name, array( $this, 'cron_exec' ) );

		if ( ! wp_next_scheduled( $this->cron_name ) ) {
			// Deal with the old pre-3.0 weekly one.
			$timestamp = wp_next_scheduled( 'jetpack_heartbeat' );
			if ( $timestamp ) {
				wp_unschedule_event( $timestamp, 'jetpack_heartbeat' );
			}

			wp_schedule_event( time(), 'daily', $this->cron_name );
		}

		add_filter( 'jetpack_xmlrpc_unauthenticated_methods', array( __CLASS__, 'jetpack_xmlrpc_methods' ) );

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			WP_CLI::add_command( 'jetpack-heartbeat', array( $this, 'cli_callback' ) );
		}
	}

	/**
	 * Method that gets executed on the wp-cron call
	 *
	 * @since 1.0.0
	 * @since-jetpack 2.3.3
	 * @global string $wp_version
	 */
	public function cron_exec() {

		$a8c_mc_stats = new A8c_Mc_Stats();

		/*
		 * This should run daily.  Figuring in for variances in
		 * WP_CRON, don't let it run more than every 23 hours at most.
		 *
		 * i.e. if it ran less than 23 hours ago, fail out.
		 */
		$last = (int) Jetpack_Options::get_option( 'last_heartbeat' );
		if ( $last && ( $last + DAY_IN_SECONDS - HOUR_IN_SECONDS > time() ) ) {
			return;
		}

		/*
		 * Check for an identity crisis
		 *
		 * If one exists:
		 * - Bump stat for ID crisis
		 * - Email site admin about potential ID crisis
		 */

		// Coming Soon!

		foreach ( self::generate_stats_array( 'v2-' ) as $key => $value ) {
			if ( is_array( $value ) ) {
				foreach ( $value as $v ) {
					$a8c_mc_stats->add( $key, (string) $v );
				}
			} else {
				$a8c_mc_stats->add( $key, (string) $value );
			}
		}

		Jetpack_Options::update_option( 'last_heartbeat', time() );

		$a8c_mc_stats->do_server_side_stats();

		/**
		 * Fires when we synchronize all registered options on heartbeat.
		 *
		 * @since 3.3.0
		 */
		do_action( 'jetpack_heartbeat' );
	}

	/**
	 * Generates heartbeat stats data.
	 *
	 * @param string $prefix Prefix to add before stats identifier.
	 *
	 * @return array The stats array.
	 */
	public static function generate_stats_array( $prefix = '' ) {

		/**
		 * This filter is used to build the array of stats that are bumped once a day by Jetpack Heartbeat.
		 *
		 * Filter the array and add key => value pairs where
		 * * key is the stat group name
		 * * value is the stat name.
		 *
		 * Example:
		 * add_filter( 'jetpack_heartbeat_stats_array', function( $stats ) {
		 *    $stats['is-https'] = is_ssl() ? 'https' : 'http';
		 * });
		 *
		 * This will bump the stats for the 'is-https/https' or 'is-https/http' stat.
		 *
		 * @param array  $stats The stats to be filtered.
		 * @param string $prefix The prefix that will automatically be added at the begining at each stat group name.
		 */
		$stats  = apply_filters( 'jetpack_heartbeat_stats_array', array(), $prefix );
		$return = array();

		// Apply prefix to stats.
		foreach ( $stats as $stat => $value ) {
			$return[ "$prefix$stat" ] = $value;
		}

		return $return;
	}

	/**
	 * Registers jetpack.getHeartbeatData xmlrpc method
	 *
	 * @param array $methods The list of methods to be filtered.
	 * @return array $methods
	 */
	public static function jetpack_xmlrpc_methods( $methods ) {
		$methods['jetpack.getHeartbeatData'] = array( __CLASS__, 'xmlrpc_data_response' );
		return $methods;
	}

	/**
	 * Handles the response for the jetpack.getHeartbeatData xmlrpc method
	 *
	 * @param array $params The parameters received in the request.
	 * @return array $params all the stats that heartbeat handles.
	 */
	public static function xmlrpc_data_response( $params = array() ) {
		// The WordPress XML-RPC server sets a default param of array()
		// if no argument is passed on the request and the method handlers get this array in $params.
		// generate_stats_array() needs a string as first argument.
		$params = empty( $params ) ? '' : $params;
		return self::generate_stats_array( $params );
	}

	/**
	 * Clear scheduled events
	 *
	 * @return void
	 */
	public function deactivate() {
		// Deal with the old pre-3.0 weekly one.
		$timestamp = wp_next_scheduled( 'jetpack_heartbeat' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'jetpack_heartbeat' );
		}

		$timestamp = wp_next_scheduled( $this->cron_name );
		wp_unschedule_event( $timestamp, $this->cron_name );
	}

	/**
	 * Interact with the Heartbeat
	 *
	 * ## OPTIONS
	 *
	 * inspect (default): Gets the list of data that is going to be sent in the heartbeat and the date/time of the last heartbeat
	 *
	 * @param array $args Arguments passed via CLI.
	 *
	 * @return void
	 */
	public function cli_callback( $args ) {

		$allowed_args = array(
			'inspect',
		);

		if ( isset( $args[0] ) && ! in_array( $args[0], $allowed_args, true ) ) {
			/* translators: %s is a command like "prompt" */
			WP_CLI::error( sprintf( __( '%s is not a valid command.', 'jetpack-connection' ), $args[0] ) );
		}

		$stats           = self::generate_stats_array();
		$formatted_stats = array();

		foreach ( $stats as $stat_name => $bin ) {
			$formatted_stats[] = array(
				'Stat name' => $stat_name,
				'Bin'       => $bin,
			);
		}

		WP_CLI\Utils\format_items( 'table', $formatted_stats, array( 'Stat name', 'Bin' ) );

		$last_heartbeat = Jetpack_Options::get_option( 'last_heartbeat' );

		if ( $last_heartbeat ) {
			$last_date = gmdate( 'Y-m-d H:i:s', $last_heartbeat );
			/* translators: %s is the full datetime of the last heart beat e.g. 2020-01-01 12:21:23 */
			WP_CLI::line( sprintf( __( 'Last heartbeat sent at: %s', 'jetpack-connection' ), $last_date ) );
		}
	}

}
