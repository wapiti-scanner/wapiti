<?php
/**
 * XMLRPC Async Call class.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Jetpack_IXR_ClientMulticall;

/**
 * Make XMLRPC async calls to WordPress.com
 *
 * This class allows you to enqueue XMLRPC calls that will be grouped and sent
 * at once in a multi-call request at shutdown.
 *
 * Usage:
 *
 * XMLRPC_Async_Call::add_call( 'methodName', get_current_user_id(), $arg1, $arg2, etc... )
 *
 * See XMLRPC_Async_Call::add_call for details
 */
class XMLRPC_Async_Call {

	/**
	 * Hold the IXR Clients that will be dispatched at shutdown
	 *
	 * Clients are stored in the following schema:
	 * [
	 *  $blog_id => [
	 *    $user_id => [
	 *      arrat of Jetpack_IXR_ClientMulticall
	 *    ]
	 *  ]
	 * ]
	 *
	 * @var array
	 */
	public static $clients = array();

	/**
	 * Adds a new XMLRPC call to the queue to be processed on shutdown
	 *
	 * @param string  $method The XML-RPC method.
	 * @param integer $user_id The user ID used to make the request (will use this user's token); Use 0 for the blog token.
	 * @param mixed   ...$args This function accepts any number of additional arguments, that will be passed to the call.
	 * @return void
	 */
	public static function add_call( $method, $user_id = 0, ...$args ) {
		global $blog_id;

		$client_blog_id = is_multisite() ? $blog_id : 0;

		if ( ! isset( self::$clients[ $client_blog_id ] ) ) {
			self::$clients[ $client_blog_id ] = array();
		}

		if ( ! isset( self::$clients[ $client_blog_id ][ $user_id ] ) ) {
			self::$clients[ $client_blog_id ][ $user_id ] = new Jetpack_IXR_ClientMulticall( array( 'user_id' => $user_id ) );
		}

		if ( function_exists( 'ignore_user_abort' ) ) {
			ignore_user_abort( true );
		}

		array_unshift( $args, $method );

		call_user_func_array( array( self::$clients[ $client_blog_id ][ $user_id ], 'addCall' ), $args );

		if ( false === has_action( 'shutdown', array( 'Automattic\Jetpack\Connection\XMLRPC_Async_Call', 'do_calls' ) ) ) {
			add_action( 'shutdown', array( 'Automattic\Jetpack\Connection\XMLRPC_Async_Call', 'do_calls' ) );
		}
	}

	/**
	 * Trigger the calls at shutdown
	 *
	 * @return void
	 */
	public static function do_calls() {
		foreach ( self::$clients as $client_blog_id => $blog_clients ) {
			if ( $client_blog_id > 0 ) {
				$switch_success = switch_to_blog( $client_blog_id, true );

				if ( ! $switch_success ) {
					continue;
				}
			}

			foreach ( $blog_clients as $client ) {
				if ( empty( $client->calls ) ) {
					continue;
				}

				flush();
				$client->query();
			}

			if ( $client_blog_id > 0 ) {
				restore_current_blog();
			}
		}
	}
}
