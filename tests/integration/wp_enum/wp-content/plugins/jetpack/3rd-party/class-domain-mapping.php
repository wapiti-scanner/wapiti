<?php
/**
 * Domain Mapping 3rd Party
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Third_Party;

use Automattic\Jetpack\Constants;

/**
 * Class Automattic\Jetpack\Third_Party\Domain_Mapping.
 *
 * This class contains methods that are used to provide compatibility between Jetpack sync and domain mapping plugins.
 */
class Domain_Mapping {

	/**
	 * Singleton holder.
	 *
	 * @var Domain_Mapping
	 **/
	private static $instance = null;

	/**
	 * An array of methods that are used to hook the Jetpack sync filters for home_url and site_url to a mapping plugin.
	 *
	 * @var array
	 */
	public static $test_methods = array(
		'hook_wordpress_mu_domain_mapping',
		'hook_wpmu_dev_domain_mapping',
	);

	/**
	 * Singleton constructor.
	 *
	 * @return Domain_Mapping|null
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Domain_Mapping();
		}

		return self::$instance;
	}

	/**
	 * Class Automattic\Jetpack\Third_Party\Domain_Mapping constructor.
	 */
	private function __construct() {
		add_action( 'plugins_loaded', array( $this, 'attempt_to_hook_domain_mapping_plugins' ) );
	}

	/**
	 * This function is called on the plugins_loaded action and will loop through the $test_methods
	 * to try and hook a domain mapping plugin to the Jetpack sync filters for the home_url and site_url callables.
	 */
	public function attempt_to_hook_domain_mapping_plugins() {
		if ( ! Constants::is_defined( 'SUNRISE' ) ) {
			return;
		}

		$hooked = false;
		$count  = count( self::$test_methods );
		for ( $i = 0; $i < $count && ! $hooked; $i++ ) {
			$hooked = call_user_func( array( $this, self::$test_methods[ $i ] ) );
		}
	}

	/**
	 * This method will test for a constant and function that are known to be used with Donncha's WordPress MU
	 * Domain Mapping plugin. If conditions are met, we hook the domain_mapping_siteurl() function to Jetpack sync
	 * filters for home_url and site_url callables.
	 *
	 * @return bool
	 */
	public function hook_wordpress_mu_domain_mapping() {
		if ( ! Constants::is_defined( 'SUNRISE_LOADED' ) || ! $this->function_exists( 'domain_mapping_siteurl' ) ) {
			return false;
		}

		add_filter( 'jetpack_sync_home_url', 'domain_mapping_siteurl' );
		add_filter( 'jetpack_sync_site_url', 'domain_mapping_siteurl' );

		return true;
	}

	/**
	 * This method will test for a class and method known to be used in WPMU Dev's domain mapping plugin. If the
	 * method exists, then we'll hook the swap_to_mapped_url() to our Jetpack sync filters for home_url and site_url.
	 *
	 * @return bool
	 */
	public function hook_wpmu_dev_domain_mapping() {
		if ( ! $this->class_exists( 'domain_map' ) || ! $this->method_exists( 'domain_map', 'utils' ) ) {
			return false;
		}

		$utils = $this->get_domain_mapping_utils_instance();
		add_filter( 'jetpack_sync_home_url', array( $utils, 'swap_to_mapped_url' ) );
		add_filter( 'jetpack_sync_site_url', array( $utils, 'swap_to_mapped_url' ) );

		return true;
	}

	/*
	 * Utility Methods
	 *
	 * These methods are very minimal, and in most cases, simply pass on arguments. Why create them you ask?
	 * So that we can test.
	 */

	/**
	 * Checks if a method exists.
	 *
	 * @param string $class Class name.
	 * @param string $method Method name.
	 *
	 * @return bool Returns function_exists() without modification.
	 */
	public function method_exists( $class, $method ) {
		return method_exists( $class, $method );
	}

	/**
	 * Checks if a class exists.
	 *
	 * @param string $class Class name.
	 *
	 * @return bool Returns class_exists() without modification.
	 */
	public function class_exists( $class ) {
		return class_exists( $class );
	}

	/**
	 * Checks if a function exists.
	 *
	 * @param string $function Function name.
	 *
	 * @return bool Returns function_exists() without modification.
	 */
	public function function_exists( $function ) {
		return function_exists( $function );
	}

	/**
	 * Returns the Domain_Map::utils() instance.
	 *
	 * @see https://github.com/wpmudev/domain-mapping/blob/master/classes/Domainmap/Utils.php
	 * @return Domainmap_Utils
	 */
	public function get_domain_mapping_utils_instance() {
		return \domain_map::utils();
	}
}

Domain_Mapping::init();
