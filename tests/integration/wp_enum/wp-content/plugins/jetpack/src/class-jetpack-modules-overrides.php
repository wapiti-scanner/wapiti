<?php
/**
 * Special cases for overriding modules.
 *
 * @package automattic/jetpack
 */

/**
 * Provides methods for dealing with module overrides.
 *
 * @since 5.9.0
 */
class Jetpack_Modules_Overrides {
	/**
	 * Used to cache module overrides so that we minimize how many times we apply the
	 * option_jetpack_active_modules filter.
	 *
	 * @var null|array
	 */
	private $overrides = null;

	/**
	 * Clears the $overrides member used for caching.
	 *
	 * Since get_overrides() can be passed a falsey value to skip caching, this is probably
	 * most useful for clearing cache between tests.
	 *
	 * @return void
	 */
	public function clear_cache() {
		$this->overrides = null;
	}

	/**
	 * Returns true if there is a filter on the jetpack_active_modules option.
	 *
	 * @return bool Whether there is a filter on the jetpack_active_modules option.
	 */
	public function do_overrides_exist() {
		return (bool) ( has_filter( 'option_jetpack_active_modules' ) || has_filter( 'jetpack_active_modules' ) );
	}

	/**
	 * Gets the override for a given module.
	 *
	 * @param string  $module_slug The module's slug.
	 * @param boolean $use_cache   Whether or not cached overrides should be used.
	 *
	 * @return bool|string False if no override for module. 'active' or 'inactive' if there is an override.
	 */
	public function get_module_override( $module_slug, $use_cache = true ) {
		$overrides = $this->get_overrides( $use_cache );

		if ( ! isset( $overrides[ $module_slug ] ) ) {
			return false;
		}

		return $overrides[ $module_slug ];
	}

	/**
	 * Returns an array of module overrides where the key is the module slug and the value
	 * is true if the module is forced on and false if the module is forced off.
	 *
	 * @param bool $use_cache Whether or not cached overrides should be used.
	 *
	 * @return array The array of module overrides.
	 */
	public function get_overrides( $use_cache = true ) {
		if ( $use_cache && $this->overrides !== null ) {
			return $this->overrides;
		}

		if ( ! $this->do_overrides_exist() ) {
			return array();
		}

		$available_modules = Jetpack::get_available_modules();

		/**
		 * First, let's get all modules that have been forced on.
		 */

		/** This filter is documented in wp-includes/option.php */
		$filtered = apply_filters( 'option_jetpack_active_modules', array() );

		/** This filter is documented in class.jetpack.php */
		$filtered = apply_filters( 'jetpack_active_modules', $filtered );

		$forced_on = array_diff( $filtered, array() );

		/**
		 * Second, let's get all modules forced off.
		 */

		/** This filter is documented in wp-includes/option.php */
		$filtered = apply_filters( 'option_jetpack_active_modules', $available_modules );

		/** This filter is documented in class.jetpack.php */
		$filtered = apply_filters( 'jetpack_active_modules', $filtered );

		$forced_off = array_diff( $available_modules, $filtered );

		/**
		 * Last, build the return value.
		 */
		$return_value = array();
		foreach ( $forced_on as $on ) {
			$return_value[ $on ] = 'active';
		}

		foreach ( $forced_off as $off ) {
			$return_value[ $off ] = 'inactive';
		}

		$this->overrides = $return_value;

		return $return_value;
	}

	/**
	 * A reference to an instance of this class.
	 *
	 * @var Jetpack_Modules_Overrides
	 */
	private static $instance = null;

	/**
	 * Returns the singleton instance of Jetpack_Modules_Overrides
	 *
	 * @return Jetpack_Modules_Overrides
	 */
	public static function instance() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Modules_Overrides();
		}

		return self::$instance;
	}

	/**
	 * Private construct to enforce singleton.
	 */
	private function __construct() {
	}
}
