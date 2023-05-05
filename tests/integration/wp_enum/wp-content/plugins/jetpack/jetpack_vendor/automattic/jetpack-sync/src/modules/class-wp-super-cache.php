<?php
/**
 * WP_Super_Cache sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

/**
 * Class to handle sync for WP_Super_Cache.
 */
class WP_Super_Cache extends Module {
	/**
	 * Constructor.
	 *
	 * @todo Should we refactor this to use $this->set_defaults() instead?
	 */
	public function __construct() {
		add_filter( 'jetpack_sync_constants_whitelist', array( $this, 'add_wp_super_cache_constants_whitelist' ), 10 );
		add_filter( 'jetpack_sync_callable_whitelist', array( $this, 'add_wp_super_cache_callable_whitelist' ), 10 );
	}

	/**
	 * Whitelist for constants we are interested to sync.
	 *
	 * @access public
	 * @static
	 *
	 * @var array
	 */
	public static $wp_super_cache_constants = array(
		'WPLOCKDOWN',
		'WPSC_DISABLE_COMPRESSION',
		'WPSC_DISABLE_LOCKING',
		'WPSC_DISABLE_HTACCESS_UPDATE',
		'ADVANCEDCACHEPROBLEM',
	);

	/**
	 * Container for the whitelist for WP_Super_Cache callables we are interested to sync.
	 *
	 * @access public
	 * @static
	 *
	 * @var array
	 */
	public static $wp_super_cache_callables = array(
		'wp_super_cache_globals' => array( __CLASS__, 'get_wp_super_cache_globals' ),
	);

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'wp-super-cache';
	}

	/**
	 * Retrieve all WP_Super_Cache callables we are interested to sync.
	 *
	 * @access public
	 *
	 * @global $wp_cache_mod_rewrite;
	 * @global $cache_enabled;
	 * @global $super_cache_enabled;
	 * @global $ossdlcdn;
	 * @global $cache_rebuild_files;
	 * @global $wp_cache_mobile;
	 * @global $wp_super_cache_late_init;
	 * @global $wp_cache_anon_only;
	 * @global $wp_cache_not_logged_in;
	 * @global $wp_cache_clear_on_post_edit;
	 * @global $wp_cache_mobile_enabled;
	 * @global $wp_super_cache_debug;
	 * @global $cache_max_time;
	 * @global $wp_cache_refresh_single_only;
	 * @global $wp_cache_mfunc_enabled;
	 * @global $wp_supercache_304;
	 * @global $wp_cache_no_cache_for_get;
	 * @global $wp_cache_mutex_disabled;
	 * @global $cache_jetpack;
	 * @global $cache_domain_mapping;
	 *
	 * @return array All WP_Super_Cache callables.
	 */
	public static function get_wp_super_cache_globals() {
		global $wp_cache_mod_rewrite;
		global $cache_enabled;
		global $super_cache_enabled;
		global $ossdlcdn;
		global $cache_rebuild_files;
		global $wp_cache_mobile;
		global $wp_super_cache_late_init;
		global $wp_cache_anon_only;
		global $wp_cache_not_logged_in;
		global $wp_cache_clear_on_post_edit;
		global $wp_cache_mobile_enabled;
		global $wp_super_cache_debug;
		global $cache_max_time;
		global $wp_cache_refresh_single_only;
		global $wp_cache_mfunc_enabled;
		global $wp_supercache_304;
		global $wp_cache_no_cache_for_get;
		global $wp_cache_mutex_disabled;
		global $cache_jetpack;
		global $cache_domain_mapping;

		return array(
			'wp_cache_mod_rewrite'         => $wp_cache_mod_rewrite,
			'cache_enabled'                => $cache_enabled,
			'super_cache_enabled'          => $super_cache_enabled,
			'ossdlcdn'                     => $ossdlcdn,
			'cache_rebuild_files'          => $cache_rebuild_files,
			'wp_cache_mobile'              => $wp_cache_mobile,
			'wp_super_cache_late_init'     => $wp_super_cache_late_init,
			'wp_cache_anon_only'           => $wp_cache_anon_only,
			'wp_cache_not_logged_in'       => $wp_cache_not_logged_in,
			'wp_cache_clear_on_post_edit'  => $wp_cache_clear_on_post_edit,
			'wp_cache_mobile_enabled'      => $wp_cache_mobile_enabled,
			'wp_super_cache_debug'         => $wp_super_cache_debug,
			'cache_max_time'               => $cache_max_time,
			'wp_cache_refresh_single_only' => $wp_cache_refresh_single_only,
			'wp_cache_mfunc_enabled'       => $wp_cache_mfunc_enabled,
			'wp_supercache_304'            => $wp_supercache_304,
			'wp_cache_no_cache_for_get'    => $wp_cache_no_cache_for_get,
			'wp_cache_mutex_disabled'      => $wp_cache_mutex_disabled,
			'cache_jetpack'                => $cache_jetpack,
			'cache_domain_mapping'         => $cache_domain_mapping,
		);
	}

	/**
	 * Add WP_Super_Cache constants to the constants whitelist.
	 *
	 * @param array $list Existing constants whitelist.
	 * @return array Updated constants whitelist.
	 */
	public function add_wp_super_cache_constants_whitelist( $list ) {
		return array_merge( $list, self::$wp_super_cache_constants );
	}

	/**
	 * Add WP_Super_Cache callables to the callables whitelist.
	 *
	 * @param array $list Existing callables whitelist.
	 * @return array Updated callables whitelist.
	 */
	public function add_wp_super_cache_callable_whitelist( $list ) {
		return array_merge( $list, self::$wp_super_cache_callables );
	}
}
