<?php
/**
 * A status class for Jetpack.
 *
 * @package automattic/jetpack-status
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Status\Cache;
use Automattic\Jetpack\Status\Host;
use WPCOM_Masterbar;

/**
 * Class Automattic\Jetpack\Status
 *
 * Used to retrieve information about the current status of Jetpack and the site overall.
 */
class Status {
	/**
	 * Is Jetpack in development (offline) mode?
	 *
	 * @deprecated 1.3.0 Use Status->is_offline_mode().
	 *
	 * @return bool Whether Jetpack's offline mode is active.
	 */
	public function is_development_mode() {
		_deprecated_function( __FUNCTION__, '1.3.0', 'Automattic\Jetpack\Status->is_offline_mode' );
		return $this->is_offline_mode();
	}

	/**
	 * Is Jetpack in offline mode?
	 *
	 * This was formerly called "Development Mode", but sites "in development" aren't always offline/localhost.
	 *
	 * @since 1.3.0
	 *
	 * @return bool Whether Jetpack's offline mode is active.
	 */
	public function is_offline_mode() {
		$cached = Cache::get( 'is_offline_mode' );
		if ( null !== $cached ) {
			return $cached;
		}

		$offline_mode = false;

		if ( defined( '\\JETPACK_DEV_DEBUG' ) ) {
			$offline_mode = constant( '\\JETPACK_DEV_DEBUG' );
		} elseif ( defined( '\\WP_LOCAL_DEV' ) ) {
			$offline_mode = constant( '\\WP_LOCAL_DEV' );
		} elseif ( $this->is_local_site() ) {
			$offline_mode = true;
		}

		/**
		 * Filters Jetpack's offline mode.
		 *
		 * @see https://jetpack.com/support/development-mode/
		 * @todo Update documentation ^^.
		 *
		 * @since 1.1.1
		 * @since-jetpack 2.2.1
		 * @deprecated 1.3.0
		 *
		 * @param bool $offline_mode Is Jetpack's offline mode active.
		 */
		$offline_mode = (bool) apply_filters_deprecated( 'jetpack_development_mode', array( $offline_mode ), '1.3.0', 'jetpack_offline_mode' );

		/**
		 * Filters Jetpack's offline mode.
		 *
		 * @see https://jetpack.com/support/development-mode/
		 * @todo Update documentation ^^.
		 *
		 * @since 1.3.0
		 *
		 * @param bool $offline_mode Is Jetpack's offline mode active.
		 */
		$offline_mode = (bool) apply_filters( 'jetpack_offline_mode', $offline_mode );

		Cache::set( 'is_offline_mode', $offline_mode );
		return $offline_mode;
	}

	/**
	 * Is Jetpack in "No User test mode"?
	 *
	 * This will make Jetpack act as if there were no connected users, but only a site connection (aka blog token)
	 *
	 * @since 1.6.0
	 * @deprecated 1.7.5 Since this version, Jetpack connection is considered active after registration, making no_user_testing_mode obsolete.
	 *
	 * @return bool Whether Jetpack's No User Testing Mode is active.
	 */
	public function is_no_user_testing_mode() {
		_deprecated_function( __METHOD__, '1.7.5' );
		return true;
	}

	/**
	 * Whether this is a system with a multiple networks.
	 * Implemented since there is no core is_multi_network function.
	 * Right now there is no way to tell which network is the dominant network on the system.
	 *
	 * @return boolean
	 */
	public function is_multi_network() {
		global $wpdb;

		$cached = Cache::get( 'is_multi_network' );
		if ( null !== $cached ) {
			return $cached;
		}

		// If we don't have a multi site setup no need to do any more.
		if ( ! is_multisite() ) {
			Cache::set( 'is_multi_network', false );
			return false;
		}

		$num_sites = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->site}" );
		if ( $num_sites > 1 ) {
			Cache::set( 'is_multi_network', true );
			return true;
		}

		Cache::set( 'is_multi_network', false );
		return false;
	}

	/**
	 * Whether the current site is single user site.
	 *
	 * @return bool
	 */
	public function is_single_user_site() {
		global $wpdb;

		$ret = Cache::get( 'is_single_user_site' );
		if ( null === $ret ) {
			$some_users = get_transient( 'jetpack_is_single_user' );
			if ( false === $some_users ) {
				$some_users = $wpdb->get_var( "SELECT COUNT(*) FROM (SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '{$wpdb->prefix}capabilities' LIMIT 2) AS someusers" );
				set_transient( 'jetpack_is_single_user', (int) $some_users, 12 * HOUR_IN_SECONDS );
			}
			$ret = 1 === (int) $some_users;
			Cache::set( 'is_single_user_site', $ret );
		}
		return $ret;
	}

	/**
	 * If the site is a local site.
	 *
	 * @since 1.3.0
	 *
	 * @return bool
	 */
	public function is_local_site() {
		$cached = Cache::get( 'is_local_site' );
		if ( null !== $cached ) {
			return $cached;
		}

		$site_url = site_url();

		// Check for localhost and sites using an IP only first.
		$is_local = $site_url && false === strpos( $site_url, '.' );

		// @todo Remove function_exists when the package has a documented minimum WP version.
		// Use Core's environment check, if available. Added in 5.5.0 / 5.5.1 (for `local` return value).
		if ( function_exists( 'wp_get_environment_type' ) && 'local' === wp_get_environment_type() ) {
			$is_local = true;
		}

		// Then check for usual usual domains used by local dev tools.
		$known_local = array(
			'#\.local$#i',
			'#\.localhost$#i',
			'#\.test$#i',
			'#\.docksal$#i',      // Docksal.
			'#\.docksal\.site$#i', // Docksal.
			'#\.dev\.cc$#i',       // ServerPress.
			'#\.lndo\.site$#i',    // Lando.
		);

		if ( ! $is_local ) {
			foreach ( $known_local as $url ) {
				if ( preg_match( $url, $site_url ) ) {
					$is_local = true;
					break;
				}
			}
		}

		/**
		 * Filters is_local_site check.
		 *
		 * @since 1.3.0
		 *
		 * @param bool $is_local If the current site is a local site.
		 */
		$is_local = apply_filters( 'jetpack_is_local_site', $is_local );

		Cache::set( 'is_local_site', $is_local );
		return $is_local;
	}

	/**
	 * If is a staging site.
	 *
	 * @todo Add IDC detection to a package.
	 *
	 * @return bool
	 */
	public function is_staging_site() {
		$cached = Cache::get( 'is_staging_site' );
		if ( null !== $cached ) {
			return $cached;
		}

		// @todo Remove function_exists when the package has a documented minimum WP version.
		// Core's wp_get_environment_type allows for a few specific options. We should default to bowing out gracefully for anything other than production or local.
		$is_staging = function_exists( 'wp_get_environment_type' ) && ! in_array( wp_get_environment_type(), array( 'production', 'local' ), true );

		$known_staging = array(
			'urls'      => array(
				'#\.staging\.wpengine\.com$#i', // WP Engine. This is their legacy staging URL structure. Their new platform does not have a common URL. https://github.com/Automattic/jetpack/issues/21504
				'#\.staging\.kinsta\.com$#i',   // Kinsta.com.
				'#\.kinsta\.cloud$#i',          // Kinsta.com.
				'#\.stage\.site$#i',            // DreamPress.
				'#\.newspackstaging\.com$#i',   // Newspack.
				'#\.pantheonsite\.io$#i',       // Pantheon.
				'#\.flywheelsites\.com$#i',     // Flywheel.
				'#\.flywheelstaging\.com$#i',   // Flywheel.
				'#\.cloudwaysapps\.com$#i',     // Cloudways.
				'#\.azurewebsites\.net$#i',     // Azure.
				'#\.wpserveur\.net$#i',         // WPServeur.
				'#\-liquidwebsites\.com$#i',    // Liquidweb.
			),
			'constants' => array(
				'IS_WPE_SNAPSHOT',      // WP Engine. This is used on their legacy staging environment. Their new platform does not have a constant. https://github.com/Automattic/jetpack/issues/21504
				'KINSTA_DEV_ENV',       // Kinsta.com.
				'WPSTAGECOACH_STAGING', // WP Stagecoach.
				'JETPACK_STAGING_MODE', // Generic.
				'WP_LOCAL_DEV',         // Generic.
			),
		);
		/**
		 * Filters the flags of known staging sites.
		 *
		 * @since 1.1.1
		 * @since-jetpack 3.9.0
		 *
		 * @param array $known_staging {
		 *     An array of arrays that each are used to check if the current site is staging.
		 *     @type array $urls      URLs of staging sites in regex to check against site_url.
		 *     @type array $constants PHP constants of known staging/developement environments.
		 *  }
		 */
		$known_staging = apply_filters( 'jetpack_known_staging', $known_staging );

		if ( isset( $known_staging['urls'] ) ) {
			$site_url = site_url();
			foreach ( $known_staging['urls'] as $url ) {
				if ( preg_match( $url, wp_parse_url( $site_url, PHP_URL_HOST ) ) ) {
					$is_staging = true;
					break;
				}
			}
		}

		if ( isset( $known_staging['constants'] ) ) {
			foreach ( $known_staging['constants'] as $constant ) {
				if ( defined( $constant ) && constant( $constant ) ) {
					$is_staging = true;
				}
			}
		}

		// Last, let's check if sync is erroring due to an IDC. If so, set the site to staging mode.
		if ( ! $is_staging && method_exists( 'Automattic\\Jetpack\\Identity_Crisis', 'validate_sync_error_idc_option' ) && \Automattic\Jetpack\Identity_Crisis::validate_sync_error_idc_option() ) {
			$is_staging = true;
		}

		/**
		 * Filters is_staging_site check.
		 *
		 * @since 1.1.1
		 * @since-jetpack 3.9.0
		 *
		 * @param bool $is_staging If the current site is a staging site.
		 */
		$is_staging = apply_filters( 'jetpack_is_staging_site', $is_staging );

		Cache::set( 'is_staging_site', $is_staging );
		return $is_staging;
	}

	/**
	 * Whether the site is currently onboarding or not.
	 * A site is considered as being onboarded if it currently has an onboarding token.
	 *
	 * @since-jetpack 5.8
	 *
	 * @access public
	 * @static
	 *
	 * @return bool True if the site is currently onboarding, false otherwise
	 */
	public function is_onboarding() {
		return \Jetpack_Options::get_option( 'onboarding' ) !== false;
	}

	/**
	 * Whether the site is currently private or not.
	 * On WordPress.com and WoA, sites can be marked as private
	 *
	 * @since 1.16.0
	 *
	 * @return bool True if the site is private.
	 */
	public function is_private_site() {
		$ret = Cache::get( 'is_private_site' );
		if ( null === $ret ) {
			$is_private_site = '-1' === get_option( 'blog_public' );

			/**
			 * Filters the is_private_site check.
			 *
			 * @since 1.16.1
			 *
			 * @param bool $is_private_site True if the site is private.
			 */
			$is_private_site = apply_filters( 'jetpack_is_private_site', $is_private_site );

			Cache::set( 'is_private_site', $is_private_site );
			return $is_private_site;
		}
		return $ret;
	}

	/**
	 * Whether the site is currently unlaunched or not.
	 * On WordPress.com and WoA, sites can be marked as "coming soon", aka unlaunched
	 *
	 * @since 1.16.0
	 *
	 * @return bool True if the site is not launched.
	 */
	public function is_coming_soon() {
		$ret = Cache::get( 'is_coming_soon' );
		if ( null === $ret ) {
			$is_coming_soon = (bool) ( function_exists( 'site_is_coming_soon' ) && \site_is_coming_soon() )
				|| get_option( 'wpcom_public_coming_soon' );

			/**
			 * Filters the is_coming_soon check.
			 *
			 * @since 1.16.1
			 *
			 * @param bool $is_coming_soon True if the site is coming soon (i.e. unlaunched).
			 */
			$is_coming_soon = apply_filters( 'jetpack_is_coming_soon', $is_coming_soon );

			Cache::set( 'is_coming_soon', $is_coming_soon );
			return $is_coming_soon;
		}
		return $ret;
	}

	/**
	 * Returns the site slug suffix to be used as part of Calypso URLs.
	 *
	 * Strips http:// or https:// from a url, replaces forward slash with ::.
	 *
	 * @since 1.6.0
	 *
	 * @param string $url Optional. URL to build the site suffix from. Default: Home URL.
	 *
	 * @return string
	 */
	public function get_site_suffix( $url = '' ) {
		// On WordPress.com, site suffixes are a bit different.
		if ( method_exists( 'WPCOM_Masterbar', 'get_calypso_site_slug' ) ) {
			return WPCOM_Masterbar::get_calypso_site_slug( get_current_blog_id() );
		}

		// Grab the 'site_url' option for WoA sites to avoid plugins to interfere with the site
		// identifier (e.g. i18n plugins may change the main url to '<DOMAIN>/<LOCALE>', but we
		// want to exclude the locale since it's not part of the site suffix).
		if ( ( new Host() )->is_woa_site() ) {
			$url = \site_url();
		}

		if ( empty( $url ) ) {
			// WordPress can be installed in subdirectories (e.g. make.wordpress.org/plugins)
			// where the 'site_url' option points to the root domain (e.g. make.wordpress.org)
			// which could collide with another site in the same domain but with WordPress
			// installed in a different subdirectory (e.g. make.wordpress.org/core). To avoid
			// such collision, we identify the site with the 'home_url' option.
			$url = \home_url();
		}

		$url = preg_replace( '#^.*?://#', '', $url );
		$url = str_replace( '/', '::', $url );

		return rtrim( $url, ':' );
	}
}
