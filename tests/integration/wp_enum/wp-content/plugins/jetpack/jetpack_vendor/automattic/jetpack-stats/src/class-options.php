<?php
/**
 * Stats Options
 *
 * @package automattic/jetpack-stats
 */

namespace Automattic\Jetpack\Stats;

use Jetpack_Options;

/**
 * Stats Options class.
 */
class Options {

	/**
	 * Option name.
	 *
	 * @var string $option_name The 'stats' option name
	 */
	const OPTION_NAME = 'stats_options';

	/**
	 * Stats Options.
	 *
	 * @var array $options An array of associated Stats options (default empty)
	 */
	protected static $options = array();

	/**
	 * Stats Get Options.
	 *
	 * @return array.
	 */
	public static function get_options() {
		// Make sure we only get options from the database once per connection.
		if ( count( self::$options ) > 0 ) {
			return self::$options;
		}

		self::$options = get_option( self::OPTION_NAME, array() );
		self::$options = array_merge( self::get_defaults(), self::$options );

		if ( self::$options['version'] < Main::STATS_VERSION ) {
			self::upgrade_options( self::$options );
		}

		return self::$options;
	}

	/**
	 * Get Stats Option..
	 *
	 * @param string $option Option name.
	 * @return mixed|null.
	 */
	public static function get_option( $option ) {
		if ( 'blog_id' === $option ) {
			return Jetpack_Options::get_option( 'id' );
		}

		$options = self::get_options();

		if ( isset( $options[ $option ] ) ) {
			return $options[ $option ];
		}

		return null;
	}

	/**
	 * Stats Set Option.
	 *
	 * @param string $option The option name.
	 * @param mixed  $value The option Value.
	 * @return bool.
	 */
	public static function set_option( $option, $value ) {
		$options = self::get_options();

		$options[ $option ] = $value;

		return self::set_options( $options );
	}

	/**
	 * Stats Set Options.
	 *
	 * @access public
	 * @param array $options Options.
	 * @return bool
	 */
	public static function set_options( $options ) {
		if ( ! is_array( $options ) ) {
			return false;
		}

		$defaults       = self::get_defaults();
		$stored_options = get_option( self::OPTION_NAME, array() );
		$all_options    = array_merge( $defaults, $stored_options );
		$options        = array_merge( $all_options, $options );

		$allowed_options = array_keys( $defaults );
		foreach ( $options as $option_name => $option_value ) {
			if ( ! in_array( $option_name, $allowed_options, true ) ) {
				unset( $options[ $option_name ] );
			}
		}

		$options['blog_id'] = Jetpack_Options::get_option( 'id' );
		$options['version'] = Main::STATS_VERSION;

		$success = update_option( self::OPTION_NAME, $options );

		if ( true === $success ) {
			self::$options = $options;
		}

		return $success;
	}

	/**
	 * Stats Upgrade Options.
	 *
	 * Ideally this should be a protected method but keeping it public
	 * to maintain backwards compatibility with stats_upgrade_options.
	 *
	 * @access public
	 * @param array $options The stats options.
	 * @return array|bool
	 */
	public static function upgrade_options( $options ) {
		if ( isset( $options['reg_users'] ) ) {
			if ( ! function_exists( 'get_editable_roles' ) ) {
				require_once ABSPATH . 'wp-admin/includes/user.php';
			}
			if ( $options['reg_users'] ) {
				$options['count_roles'] = array_keys( get_editable_roles() );
			}
			unset( $options['reg_users'] );
		}

		if ( false === self::set_options( $options ) ) {
			return false;
		}

		return self::$options;
	}

	/**
	 * Default Stats related options.
	 *
	 * @return array
	 */
	protected static function get_defaults() {
		return array(
			'admin_bar'                => true,
			'roles'                    => array( 'administrator' ),
			'count_roles'              => array(),
			'do_not_track'             => true, // @todo
			'blog_id'                  => Jetpack_Options::get_option( 'id' ),
			'version'                  => Main::STATS_VERSION,
			'collapse_nudges'          => false,
			'enable_odyssey_stats'     => true,
			'odyssey_stats_changed_at' => 0,
			'notices'                  => array(),
			'views'                    => 0,
		);
	}
}
