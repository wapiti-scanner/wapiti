<?php
/**
 * Keyring helper.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize;

use Automattic\Jetpack\Connection\Secrets;
use Automattic\Jetpack\Paths;
use Jetpack_IXR_Client;
use Jetpack_Options;

/**
 * A series of utilities to interact with a Keyring instance.
 */
class Keyring_Helper {
	/**
	 * Class instance
	 *
	 * @var \Automattic\Jetpack\Publicize\Keyring_Helper
	 */
	private static $instance = null;

	/**
	 * Whether the `sharing` page is registered.
	 *
	 * @var bool
	 */
	private static $is_sharing_page_registered = false;

	/**
	 * Initialize instance.
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Keyring_Helper();
		}

		return self::$instance;
	}

	const SERVICES = array(
		'facebook'                 => array(
			'for' => 'publicize',
		),
		'twitter'                  => array(
			'for' => 'publicize',
		),
		'linkedin'                 => array(
			'for' => 'publicize',
		),
		'tumblr'                   => array(
			'for' => 'publicize',
		),
		'path'                     => array(
			'for' => 'publicize',
		),
		'google_plus'              => array(
			'for' => 'publicize',
		),
		'google_site_verification' => array(
			'for' => 'other',
		),
	);

	/**
	 * Constructor
	 */
	private function __construct() {
		add_action( 'admin_menu', array( __CLASS__, 'register_sharing_page' ) );

		add_action( 'load-settings_page_sharing', array( __CLASS__, 'admin_page_load' ), 9 );
	}

	/**
	 * We need a `sharing` page to be able to connect and disconnect services.
	 */
	public static function register_sharing_page() {
		if ( self::$is_sharing_page_registered ) {
			return;
		}

		self::$is_sharing_page_registered = true;

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		global $_registered_pages;

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$hookname = get_plugin_page_hookname( 'sharing', 'options-general.php' );
		add_action( $hookname, array( __CLASS__, 'admin_page_load' ) );
		$_registered_pages[ $hookname ] = true; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	}

	/**
	 * Gets a URL to the public-api actions. Works like WP's admin_url.
	 * On WordPress.com this is/calls Keyring::admin_url.
	 *
	 * @param string $service Shortname of a specific service.
	 * @param array  $params  Parameters to append to an API connection URL.
	 *
	 * @return URL to specific public-api process
	 */
	private static function api_url( $service = false, $params = array() ) {
		/**
		 * Filters the API URL used to interact with WordPress.com.
		 *
		 * @since 0.1.0
		 * @since-jetpack 2.0.0
		 *
		 * @param string https://public-api.wordpress.com/connect/?jetpack=publicize Default Publicize API URL.
		 */
		$url = apply_filters( 'publicize_api_url', 'https://public-api.wordpress.com/connect/?jetpack=publicize' );

		if ( $service ) {
			$url = add_query_arg( array( 'service' => $service ), $url );
		}

		if ( count( $params ) ) {
			$url = add_query_arg( $params, $url );
		}

		return $url;
	}

	/**
	 * Build a connection URL (sharing settings page with unique query args to create a connection).
	 *
	 * @param string $service_name Service name.
	 * @param string $for          Feature name.
	 */
	public static function connect_url( $service_name, $for ) {
		return add_query_arg(
			array(
				'action'   => 'request',
				'service'  => $service_name,
				'kr_nonce' => wp_create_nonce( 'keyring-request' ),
				'nonce'    => wp_create_nonce( "keyring-request-$service_name" ),
				'for'      => $for,
			),
			admin_url( 'options-general.php?page=sharing' )
		);
	}

	/**
	 * Build a URL to refresh a connection (sharing settings page with unique query args to refresh a connection).
	 * Similar to connect_url, but with a refresh parameter.
	 *
	 * @param string $service_name Service name.
	 * @param string $for          Feature name.
	 */
	public static function refresh_url( $service_name, $for ) {
		return add_query_arg(
			array(
				'action'   => 'request',
				'service'  => $service_name,
				'kr_nonce' => wp_create_nonce( 'keyring-request' ),
				'refresh'  => 1,
				'for'      => $for,
				'nonce'    => wp_create_nonce( "keyring-request-$service_name" ),
			),
			admin_url( 'options-general.php?page=sharing' )
		);
	}

	/**
	 * Build a URL to delete a connection (sharing settings page with unique query args to delete a connection).
	 *
	 * @param string $service_name Service name.
	 * @param string $id           Connection ID.
	 */
	public static function disconnect_url( $service_name, $id ) {
		return add_query_arg(
			array(
				'action'   => 'delete',
				'service'  => $service_name,
				'id'       => $id,
				'kr_nonce' => wp_create_nonce( 'keyring-request' ),
				'nonce'    => wp_create_nonce( "keyring-request-$service_name" ),
			),
			admin_url( 'options-general.php?page=sharing' )
		);
	}

	/**
	 * Build contents handling Keyring connection management into Sharing settings screen.
	 */
	public static function admin_page_load() {
		if ( isset( $_GET['action'] ) ) {
			if ( isset( $_GET['service'] ) ) {
				$service_name = filter_var( wp_unslash( $_GET['service'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- We verify below.
			}

			switch ( $_GET['action'] ) {

				case 'request':
					check_admin_referer( 'keyring-request', 'kr_nonce' );
					check_admin_referer( "keyring-request-$service_name", 'nonce' );

					$verification = ( new Secrets() )->generate( 'publicize' );
					if ( ! $verification ) {
						$url = ( new Paths() )->admin_url( 'page=jetpack#/settings' );
						wp_die(
							sprintf(
								wp_kses(
									/* Translators: placeholder is a URL to a Settings page. */
									__( "Jetpack is not connected. Please connect Jetpack by visiting <a href='%s'>Settings</a>.", 'jetpack-publicize-pkg' ),
									array(
										'a' => array(
											'href' => array(),
										),
									)
								),
								esc_url( $url )
							)
						);

					}
					$stats_options = get_option( 'stats_options' );
					$wpcom_blog_id = Jetpack_Options::get_option( 'id' );
					$wpcom_blog_id = ! empty( $wpcom_blog_id ) ? $wpcom_blog_id : $stats_options['blog_id'];

					$user     = wp_get_current_user();
					$redirect = self::api_url(
						$service_name,
						urlencode_deep(
							array(
								'action'       => 'request',
								'redirect_uri' => add_query_arg( array( 'action' => 'done' ), menu_page_url( 'sharing', false ) ),
								'for'          => 'publicize',
								// required flag that says this connection is intended for publicize.
								'siteurl'      => site_url(),
								'state'        => $user->ID,
								'blog_id'      => $wpcom_blog_id,
								'secret_1'     => $verification['secret_1'],
								'secret_2'     => $verification['secret_2'],
								'eol'          => $verification['exp'],
							)
						)
					);
					wp_redirect( $redirect ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- The API URL is an external URL and is filterable.
					exit;

				case 'completed':
					/*
					 * We do not use a nonce here,
					 * since we're populating a local cache of
					 * the Publicize connections that were created and stored on WordPress.com.
					 */
					$xml = new Jetpack_IXR_Client();
					$xml->query( 'jetpack.fetchPublicizeConnections' );

					if ( ! $xml->isError() ) {
						$response = $xml->getResponse();
						Jetpack_Options::update_option( 'publicize_connections', $response );
					}

					break;

				case 'delete':
					$id = isset( $_GET['id'] ) ? filter_var( wp_unslash( $_GET['id'] ) ) : null;

					check_admin_referer( 'keyring-request', 'kr_nonce' );
					check_admin_referer( "keyring-request-$service_name", 'nonce' );

					self::disconnect( $service_name, $id );

					do_action( 'connection_disconnected', $service_name );
					break;
			}
		}
	}

	/**
	 * Remove a Publicize connection
	 *
	 * @param string   $service_name  Service name.
	 * @param string   $connection_id Connection ID.
	 * @param int|bool $_blog_id      Blog ID.
	 * @param int|bool $_user_id      User ID.
	 * @param bool     $force_delete  Force delete the connection.
	 */
	public static function disconnect( $service_name, $connection_id, $_blog_id = false, $_user_id = false, $force_delete = false ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$xml = new Jetpack_IXR_Client();
		$xml->query( 'jetpack.deletePublicizeConnection', $connection_id );

		if ( ! $xml->isError() ) {
			Jetpack_Options::update_option( 'publicize_connections', $xml->getResponse() );
		} else {
			return false;
		}
	}
}
