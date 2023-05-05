<?php
/**
 * A Terms of Service class for Jetpack.
 *
 * @package automattic/jetpack-licensing
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Licensing\Endpoints;
use Jetpack_IXR_ClientMulticall;
use Jetpack_Options;
use WP_Error;

/**
 * Class Licensing.
 * Helper class that is responsible for attaching licenses to the current site.
 *
 * @since 1.1.1
 */
class Licensing {
	/**
	 * Name of the WordPress option that holds all known Jetpack licenses.
	 *
	 * @const string
	 */
	const LICENSES_OPTION_NAME = 'jetpack_licenses';

	/**
	 * Name of the WordPress transient that holds the last license attaching error, if any.
	 *
	 * @const string
	 */
	const ERROR_TRANSIENT_NAME = 'jetpack_licenses_error';

	/**
	 * Holds the singleton instance of this class.
	 *
	 * @var self
	 */
	protected static $instance = false;

	/**
	 * Singleton.
	 *
	 * @static
	 */
	public static function instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Initialize.
	 *
	 * @return void
	 */
	public function initialize() {
		add_action( 'add_option_' . self::LICENSES_OPTION_NAME, array( $this, 'attach_stored_licenses' ) );
		add_action( 'update_option_' . self::LICENSES_OPTION_NAME, array( $this, 'attach_stored_licenses' ) );
		add_action( 'jetpack_authorize_ending_authorized', array( $this, 'attach_stored_licenses_on_connection' ) );
		add_action( 'rest_api_init', array( $this, 'initialize_endpoints' ) );
	}

	/**
	 * Initialize endpoints required for Licensing package.
	 *
	 * @since 1.7.0
	 *
	 * @return void
	 */
	public function initialize_endpoints() {
		$endpoints = new Endpoints();
		$endpoints->register_endpoints();
	}

	/**
	 * Get Jetpack connection manager instance.
	 *
	 * @return Connection_Manager
	 */
	protected function connection() {
		static $connection;

		if ( null === $connection ) {
			$connection = new Connection_Manager();
		}

		return $connection;
	}

	/**
	 * Get the last license attach request error that has occurred, if any.
	 *
	 * @return string Human-readable error message or an empty string.
	 */
	public function last_error() {
		return Jetpack_Options::get_option( 'licensing_error', '' );
	}

	/**
	 * Log an error to be surfaced to the user at a later time.
	 *
	 * @param string $error Human-readable error message.
	 * @return void
	 */
	public function log_error( $error ) {
		$substr = function_exists( 'mb_substr' ) ? 'mb_substr' : 'substr';
		Jetpack_Options::update_option( 'licensing_error', $substr( $error, 0, 1024 ) );
	}

	/**
	 * Get all stored licenses.
	 *
	 * @return string[] License keys.
	 */
	public function stored_licenses() {
		$licenses = (array) get_option( self::LICENSES_OPTION_NAME, array() );
		$licenses = array_filter( $licenses, 'is_scalar' );
		$licenses = array_map( 'strval', $licenses );
		$licenses = array_filter( $licenses );

		return $licenses;
	}

	/**
	 * Append a license
	 *
	 * @param string $license A jetpack license key.
	 * @return bool True if the option was updated with the new license, false otherwise.
	 */
	public function append_license( $license ) {
		$licenses = $this->stored_licenses();

		array_push( $licenses, $license );

		return update_option( self::LICENSES_OPTION_NAME, $licenses );
	}

	/**
	 * Make an authenticated WP.com XMLRPC multicall request to attach the provided license keys.
	 *
	 * @param string[] $licenses License keys to attach.
	 * @return Jetpack_IXR_ClientMulticall
	 */
	protected function attach_licenses_request( array $licenses ) {
		$xml = new Jetpack_IXR_ClientMulticall( array( 'timeout' => 30 ) );

		foreach ( $licenses as $license ) {
			$xml->addCall( 'jetpack.attachLicense', $license );
		}

		$xml->query();

		return $xml;
	}

	/**
	 * Attach the given licenses.
	 *
	 * @param string[] $licenses Licenses to attach.
	 * @return array|WP_Error Results for each license (which may include WP_Error instances) or a WP_Error instance.
	 */
	public function attach_licenses( array $licenses ) {
		if ( ! $this->connection()->has_connected_owner() ) {
			return new WP_Error( 'not_connected', __( 'Jetpack doesn\'t have a connected owner.', 'jetpack-licensing' ) );
		}

		if ( empty( $licenses ) ) {
			return array();
		}

		$xml = $this->attach_licenses_request( $licenses );

		if ( $xml->isError() ) {
			$error = new WP_Error( 'request_failed', __( 'License attach request failed.', 'jetpack-licensing' ) );
			$error->add( $xml->getErrorCode(), $xml->getErrorMessage() );
			return $error;
		}

		$results = array_map(
			function ( $response ) {
				if ( isset( $response['faultCode'] ) || isset( $response['faultString'] ) ) {
					return new WP_Error( $response['faultCode'], $response['faultString'] );
				}

				return $response;
			},
			(array) $xml->getResponse()
		);

		return $results;
	}

	/**
	 * Attach all stored licenses.
	 *
	 * @return array|WP_Error Results for each license (which may include WP_Error instances) or a WP_Error instance.
	 */
	public function attach_stored_licenses() {
		$licenses = $this->stored_licenses();
		$results  = $this->attach_licenses( $licenses );

		if ( is_wp_error( $results ) ) {
			if ( 'request_failed' === $results->get_error_code() ) {
				$this->log_error(
					__( 'Failed to attach your Jetpack license(s). Please try reconnecting Jetpack.', 'jetpack-licensing' )
				);
			}

			return $results;
		}

		$failed = array();

		foreach ( $results as $index => $result ) {
			if ( isset( $licenses[ $index ] ) && is_wp_error( $result ) ) {
				$failed[] = $licenses[ $index ];
			}
		}

		if ( ! empty( $failed ) ) {
			$this->log_error(
				sprintf(
					/* translators: %s is a comma-separated list of license keys. */
					__( 'The following Jetpack licenses are invalid, already in use, or revoked: %s', 'jetpack-licensing' ),
					implode( ', ', $failed )
				)
			);
		}

		return $results;
	}

	/**
	 * Attach all stored licenses during connection flow for the connection owner.
	 *
	 * @return void
	 */
	public function attach_stored_licenses_on_connection() {
		if ( $this->connection()->is_connection_owner() ) {
			$this->attach_stored_licenses();
		}
	}

	/**
	 * Is the current user allowed to use the Licensing Input UI?
	 *
	 * @since 1.4.0
	 * @return bool
	 */
	public static function is_licensing_input_enabled() {
		/**
		 * Filter that checks if the user is allowed to see the Licensing UI. `true` enables it.
		 *
		 * @since 1.4.0
		 *
		 * @param bool False by default.
		 */
		return apply_filters( 'jetpack_licensing_ui_enabled', false ) && current_user_can( 'jetpack_connect_user' );
	}

	/**
	 * Gets the user-licensing activation notice dismissal info.
	 *
	 * @since 10.4.0
	 * @return array
	 */
	public function get_license_activation_notice_dismiss() {

		$default = array(
			'last_detached_count' => null,
			'last_dismissed_time' => null,
		);

		if ( $this->connection()->is_user_connected() && $this->connection()->is_connection_owner() ) {
			return Jetpack_Options::get_option( 'licensing_activation_notice_dismiss', $default );
		}

		return $default;
	}

	/**
	 * Load current user's licenses.
	 *
	 * @param bool $unattached_only Only return unattached licenses.
	 *
	 * @return array
	 */
	public function get_user_licenses( $unattached_only = false ) {
		$licenses = Endpoints::get_user_licenses();

		if ( empty( $licenses->items ) ) {
			return array();
		}

		$items = $licenses->items;

		if ( $unattached_only ) {
			$items = array_filter(
				$items,
				static function ( $item ) {
					return $item->attached_at === null;
				}
			);
		}

		return $items;
	}

	/**
	 * If the destination URL is checkout page,
	 * see if there are unattached licenses they could use instead of getting a new one.
	 * If found, redirect the user to license activation.
	 *
	 * @param string $dest_url User's destination URL.
	 *
	 * @return void
	 */
	public function handle_user_connected_redirect( $dest_url ) {
		if ( ! preg_match( '#^https://[^/]+/checkout/#i', $dest_url ) ) {
			return;
		}

		$licenses    = $this->get_user_licenses( true );
		$plugin_slug = null;

		$query_string = wp_parse_url( $dest_url, PHP_URL_QUERY );
		if ( $query_string ) {
			parse_str( $query_string, $query_args );

			if ( $query_args['redirect_to']
				&& preg_match( '/^admin\.php\?page=(jetpack-\w+)/i', $query_args['redirect_to'], $matches )
			) {
				$plugin_slug = $matches[1];
			}
		}

		/**
		 * Check for the user's unattached licenses.
		 *
		 * @since 3.8.2
		 *
		 * @param bool   $has_license Whether a license was already found.
		 * @param array  $licenses Unattached licenses belonging to the user.
		 * @param string $plugin_slug Slug of the plugin that initiated the flow.
		 */
		if ( $plugin_slug && count( $licenses )
			&& apply_filters( 'jetpack_connection_user_has_license', false, $licenses, $plugin_slug )
		) {
			wp_safe_redirect( '/wp-admin/admin.php?page=my-jetpack#/add-license' );
			exit;
		}
	}
}
