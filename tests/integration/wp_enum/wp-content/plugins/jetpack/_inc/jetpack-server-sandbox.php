<?php
/**
 * This feature is only useful for Automattic developers.
 * It configures Jetpack to talk to staging/sandbox servers
 * on WordPress.com instead of production servers.
 *
 * @package automattic/jetpack
 */

/**
 * Provides sandbox request parameters.
 *
 * @param string $sandbox Sandbox domain.
 * @param string $url URL of request about to be made.
 * @param array  $headers Headers of request about to be made.
 * @return array [ 'url' => new URL, 'host' => new Host ].
 */
function jetpack_server_sandbox_request_parameters( $sandbox, $url, $headers ) {
	_deprecated_function( __METHOD__, 'jetpack-10.2', 'Automattic\\Jetpack\\Server_Sandbox::server_sandbox_request_parameters' );

	return ( new Automattic\Jetpack\Server_Sandbox() )->server_sandbox_request_parameters( $sandbox, $url, $headers );
}

/**
 * Modifies parameters of request in order to send the request to the
 * server specified by `JETPACK__SANDBOX_DOMAIN`.
 *
 * Attached to the `requests-requests.before_request` filter.
 *
 * @param string $url URL of request about to be made.
 * @param array  $headers Headers of request about to be made.
 * @return void
 */
function jetpack_server_sandbox( &$url, &$headers ) {
	_deprecated_function( __METHOD__, 'jetpack-10.2', 'Automattic\\Jetpack\\Server_Sandbox::server_sandbox' );

	( new Automattic\Jetpack\Server_Sandbox() )->server_sandbox( $url, $headers );
}
