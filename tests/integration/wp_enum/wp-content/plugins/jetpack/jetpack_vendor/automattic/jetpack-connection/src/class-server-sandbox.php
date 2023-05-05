<?php
/**
 * The Server_Sandbox class.
 *
 * This feature is only useful for Automattic developers.
 * It configures Jetpack to talk to staging/sandbox servers
 * on WordPress.com instead of production servers.
 *
 * @package automattic/jetpack-sandbox
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Constants;

/**
 * The Server_Sandbox class.
 */
class Server_Sandbox {

	/**
	 * Sets up the action hooks for the server sandbox.
	 */
	public function init() {
		if ( did_action( 'jetpack_server_sandbox_init' ) ) {
			return;
		}

		add_action( 'requests-requests.before_request', array( $this, 'server_sandbox' ), 10, 4 );
		add_action( 'admin_bar_menu', array( $this, 'admin_bar_add_sandbox_item' ), 999 );

		/**
		 * Fires when the server sandbox is initialized. This action is used to ensure that
		 * the server sandbox action hooks are set up only once.
		 *
		 * @since 1.30.7
		 */
		do_action( 'jetpack_server_sandbox_init' );
	}

	/**
	 * Returns the new url and host values.
	 *
	 * @param string $sandbox Sandbox domain.
	 * @param string $url URL of request about to be made.
	 * @param array  $headers Headers of request about to be made.
	 * @param string $data The body of request about to be made.
	 * @param string $method The method of request about to be made.
	 *
	 * @return array [ 'url' => new URL, 'host' => new Host, 'new_signature => New signature if url was changed ]
	 */
	public function server_sandbox_request_parameters( $sandbox, $url, $headers, $data = null, $method = 'GET' ) {
		$host          = '';
		$new_signature = '';

		if ( ! is_string( $sandbox ) || ! is_string( $url ) ) {
			return array(
				'url'           => $url,
				'host'          => $host,
				'new_signature' => $new_signature,
			);
		}

		$url_host = wp_parse_url( $url, PHP_URL_HOST );

		switch ( $url_host ) {
			case 'public-api.wordpress.com':
			case 'jetpack.wordpress.com':
			case 'jetpack.com':
			case 'dashboard.wordpress.com':
				$host         = isset( $headers['Host'] ) ? $headers['Host'] : $url_host;
				$original_url = $url;
				$url          = preg_replace(
					'@^(https?://)' . preg_quote( $url_host, '@' ) . '(?=[/?#].*|$)@',
					'${1}' . $sandbox,
					$url,
					1
				);

				/**
				 * Whether to add the X Debug query parameter to the request made to the Sandbox
				 *
				 * @since 1.36.0
				 *
				 * @param bool   $add_parameter Whether to add the parameter to the request or not. Default is to false.
				 * @param string $url The URL of the request being made.
				 * @param string $host The host of the request being made.
				*/
				if ( apply_filters( 'jetpack_sandbox_add_profile_parameter', false, $url, $host ) ) {
					$url = add_query_arg( 'XDEBUG_PROFILE', 1, $url );

					// URL has been modified since the signature was created. We'll need a new one.
					$original_url  = add_query_arg( 'XDEBUG_PROFILE', 1, $original_url );
					$new_signature = $this->get_new_signature( $original_url, $headers, $data, $method );

				}
		}

		return compact( 'url', 'host', 'new_signature' );
	}

	/**
	 * Gets a new signature for the request
	 *
	 * @param string $url The new URL to be signed.
	 * @param array  $headers The headers of the request about to be made.
	 * @param string $data The body of request about to be made.
	 * @param string $method The method of the request about to be made.
	 * @return string|null
	 */
	private function get_new_signature( $url, $headers, $data, $method ) {

		if ( ! empty( $headers['Authorization'] ) ) {
			$a_headers = $this->extract_authorization_headers( $headers );
			if ( ! empty( $a_headers ) ) {
				$token_details = explode( ':', $a_headers['token'] );

				if ( count( $token_details ) === 3 ) {
					$user_id           = $token_details[2];
					$token             = ( new Tokens() )->get_access_token( $user_id );
					$time_diff         = (int) \Jetpack_Options::get_option( 'time_diff' );
					$jetpack_signature = new \Jetpack_Signature( $token->secret, $time_diff );

					$signature = $jetpack_signature->sign_request(
						$a_headers['token'],
						$a_headers['timestamp'],
						$a_headers['nonce'],
						$a_headers['body-hash'],
						$method,
						$url,
						$data,
						false
					);

					if ( $signature && ! is_wp_error( $signature ) ) {
						return $signature;
					} elseif ( is_wp_error( $signature ) ) {
						$this->log_new_signature_error( $signature->get_error_message() );
					}
				} else {
					$this->log_new_signature_error( 'Malformed token on Authorization Header' );
				}
			} else {
				$this->log_new_signature_error( 'Error extracting Authorization Header' );
			}
		} else {
			$this->log_new_signature_error( 'Empty Authorization Header' );
		}
	}

	/**
	 * Logs error if the attempt to create a new signature fails
	 *
	 * @param string $message The error message.
	 * @return void
	 */
	private function log_new_signature_error( $message ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( sprintf( "SANDBOXING: Error re-signing the request. '%s'", $message ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}

	/**
	 * Extract the values in the Authorization header into an array
	 *
	 * @param array $headers The headers of the request about to be made.
	 * @return array|null
	 */
	public function extract_authorization_headers( $headers ) {
		if ( ! empty( $headers['Authorization'] ) && is_string( $headers['Authorization'] ) ) {
			$header = str_replace( 'X_JETPACK ', '', $headers['Authorization'] );
			$vars   = explode( ' ', $header );
			$result = array();
			foreach ( $vars as $var ) {
				$elements = explode( '"', $var );
				if ( count( $elements ) === 3 ) {
					$result[ substr( $elements[0], 0, -1 ) ] = $elements[1];
				}
			}
			return $result;
		}
	}

	/**
	 * Modifies parameters of request in order to send the request to the
	 * server specified by `JETPACK__SANDBOX_DOMAIN`.
	 *
	 * Attached to the `requests-requests.before_request` filter.
	 *
	 * @param string       $url URL of request about to be made.
	 * @param array        $headers Headers of request about to be made.
	 * @param array|string $data Data of request about to be made.
	 * @param string       $type Type of request about to be made.
	 * @return void
	 */
	public function server_sandbox( &$url, &$headers, &$data = null, &$type = null ) {
		if ( ! Constants::get_constant( 'JETPACK__SANDBOX_DOMAIN' ) ) {
			return;
		}

		$original_url = $url;

		$request_parameters = $this->server_sandbox_request_parameters( Constants::get_constant( 'JETPACK__SANDBOX_DOMAIN' ), $url, $headers, $data, $type );

		$url = $request_parameters['url'];

		if ( $request_parameters['host'] ) {
			$headers['Host'] = $request_parameters['host'];

			if ( $request_parameters['new_signature'] ) {
				$headers['Authorization'] = preg_replace( '/signature=\"[^\"]+\"/', 'signature="' . $request_parameters['new_signature'] . '"', $headers['Authorization'] );
			}

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( sprintf( "SANDBOXING via '%s': '%s'", Constants::get_constant( 'JETPACK__SANDBOX_DOMAIN' ), $original_url ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		}
	}

	/**
	 * Adds a "Jetpack API Sandboxed" item to the admin bar if the JETPACK__SANDBOX_DOMAIN
	 * constant is set.
	 *
	 * Attached to the `admin_bar_menu` action.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar The WP_Admin_Bar instance.
	 */
	public function admin_bar_add_sandbox_item( $wp_admin_bar ) {
		if ( ! Constants::get_constant( 'JETPACK__SANDBOX_DOMAIN' ) ) {
			return;
		}

		$node = array(
			'id'    => 'jetpack-connection-api-sandbox',
			'title' => 'Jetpack API Sandboxed',
			'meta'  => array(
				'title' => 'Sandboxing via ' . Constants::get_constant( 'JETPACK__SANDBOX_DOMAIN' ),
			),
		);

		$wp_admin_bar->add_menu( $node );
	}
}
