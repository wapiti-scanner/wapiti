<?php
/**
 * Sets up the Connection XML-RPC methods.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

/**
 * Registers the XML-RPC methods for Connections.
 */
class XMLRPC_Connector {
	/**
	 * The Connection Manager.
	 *
	 * @var Manager
	 */
	private $connection;

	/**
	 * Constructor.
	 *
	 * @param Manager $connection The Connection Manager.
	 */
	public function __construct( Manager $connection ) {
		$this->connection = $connection;

		// Adding the filter late to avoid being overwritten by Jetpack's XMLRPC server.
		add_filter( 'xmlrpc_methods', array( $this, 'xmlrpc_methods' ), 20 );
	}

	/**
	 * Attached to the `xmlrpc_methods` filter.
	 *
	 * @param array $methods The already registered XML-RPC methods.
	 * @return array
	 */
	public function xmlrpc_methods( $methods ) {
		return array_merge(
			$methods,
			array(
				'jetpack.verifyRegistration' => array( $this, 'verify_registration' ),
			)
		);
	}

	/**
	 * Handles verification that a site is registered.
	 *
	 * @param array $registration_data The data sent by the XML-RPC client:
	 *                                 [ $secret_1, $user_id ].
	 *
	 * @return string|IXR_Error
	 */
	public function verify_registration( $registration_data ) {
		return $this->output( $this->connection->handle_registration( $registration_data ) );
	}

	/**
	 * Normalizes output for XML-RPC.
	 *
	 * @param mixed $data The data to output.
	 */
	private function output( $data ) {
		if ( is_wp_error( $data ) ) {
			$code = $data->get_error_data();
			if ( ! $code ) {
				$code = -10520;
			}

			if ( ! class_exists( \IXR_Error::class ) ) {
				require_once ABSPATH . WPINC . '/class-IXR.php';
			}
			return new \IXR_Error(
				$code,
				sprintf( 'Jetpack: [%s] %s', $data->get_error_code(), $data->get_error_message() )
			);
		}

		return $data;
	}
}
