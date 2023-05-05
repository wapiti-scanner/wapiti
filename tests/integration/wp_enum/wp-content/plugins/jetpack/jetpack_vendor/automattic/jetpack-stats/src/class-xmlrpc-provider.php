<?php
/**
 * The Stats XMLRPC Provider class
 *
 * @package automattic/jetpack-stats
 */

namespace Automattic\Jetpack\Stats;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Modules;

/**
 * Stats XMLRPC Provider.
 *
 * Adds additional methods to the WordPress XML-RPC API for handling Stats specific features.
 *
 * @since 0.1.0
 */
class XMLRPC_Provider {

	/**
	 * Singleton XMLRPC_Provider instance.
	 *
	 * @var XMLRPC_Provider
	 **/
	private static $instance = null;

	/**
	 * Private XMLRPC_Provider constructor.
	 *
	 * Use the XMLRPC_Provider::init() method to get an instance.
	 */
	private function __construct() {
		add_filter( 'jetpack_xmlrpc_unauthenticated_methods', array( $this, 'xmlrpc_methods' ), 10, 3 );
	}

	/**
	 * Initialize class and get back a singleton instance.
	 *
	 * @return XMLRPC_Provider
	 */
	public static function init() {
		if ( null === self::$instance ) {
			self::$instance = new XMLRPC_Provider();
		}

		return self::$instance;
	}

	/**
	 * Adds additional methods to the WordPress xmlrpc API for handling Stats specific features.
	 *
	 * @param array $methods The Jetpack API methods.
	 *
	 * @return array
	 */
	public function xmlrpc_methods( $methods ) {
		if ( ! ( new Connection_Manager() )->is_connected() ) {
			return $methods;
		}

		if ( ! ( new Modules() )->is_active( 'stats' ) ) {
			return $methods;
		}

		$methods['jetpack.getBlog'] = array( $this, 'get_blog' );

		return $methods;
	}

	/**
	 * Stats Get Blog.
	 *
	 * @return array
	 */
	public function get_blog() {
		$home = wp_parse_url( trailingslashit( get_option( 'home' ) ) );
		$blog = array(
			'host'                => $home['host'],
			'path'                => $home['path'],
			'blogname'            => get_option( 'blogname' ),
			'blogdescription'     => get_option( 'blogdescription' ),
			'siteurl'             => get_option( 'siteurl' ),
			'gmt_offset'          => get_option( 'gmt_offset' ),
			'timezone_string'     => get_option( 'timezone_string' ),
			'stats_version'       => Main::STATS_VERSION,
			'stats_api'           => 'jetpack',
			'page_on_front'       => get_option( 'page_on_front' ),
			'permalink_structure' => get_option( 'permalink_structure' ),
			'category_base'       => get_option( 'category_base' ),
			'tag_base'            => get_option( 'tag_base' ),
		);
		$blog = array_merge( Options::get_options(), $blog );
		unset( $blog['roles'], $blog['blog_id'] );

		add_filter( 'esc_html', array( $this, 'filter_esc_html_check_if_string' ), 10, 2 );
		$blog = map_deep( $blog, 'esc_html' );
		remove_filter( 'esc_html', array( $this, 'filter_esc_html_check_if_string' ) );

		return $blog;
	}

	/**
	 * Make sure we are only escaping html if the input is a string.
	 * Used for `esc_html` filter-hook.
	 *
	 * @param  string $safe_text The output after esc_html has been applied.
	 * @param  mixed  $text      The initial input.
	 * @return mixed
	 */
	public function filter_esc_html_check_if_string( $safe_text, $text ) {
		if ( is_string( $text ) ) {
			return $safe_text;
		}

		return $text;
	}
}
