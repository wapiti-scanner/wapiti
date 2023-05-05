<?php
/**
 * The Jetpack Connection package Urls class file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Constants;

/**
 * Provides Url methods for the Connection package.
 */
class Urls {

	const HTTPS_CHECK_OPTION_PREFIX = 'jetpack_sync_https_history_';
	const HTTPS_CHECK_HISTORY       = 5;

	/**
	 * Return URL from option or PHP constant.
	 *
	 * @param string $option_name (e.g. 'home').
	 *
	 * @return mixed|null URL.
	 */
	public static function get_raw_url( $option_name ) {
		$value    = null;
		$constant = ( 'home' === $option_name )
			? 'WP_HOME'
			: 'WP_SITEURL';

		// Since we disregard the constant for multisites in ms-default-filters.php,
		// let's also use the db value if this is a multisite.
		if ( ! is_multisite() && Constants::is_defined( $constant ) ) {
			$value = Constants::get_constant( $constant );
		} else {
			// Let's get the option from the database so that we can bypass filters. This will help
			// ensure that we get more uniform values.
			$value = \Jetpack_Options::get_raw_option( $option_name );
		}

		return $value;
	}

	/**
	 * Normalize domains by removing www unless declared in the site's option.
	 *
	 * @param string   $option Option value from the site.
	 * @param callable $url_function Function retrieving the URL to normalize.
	 * @return mixed|string URL.
	 */
	public static function normalize_www_in_url( $option, $url_function ) {
		$url        = wp_parse_url( call_user_func( $url_function ) );
		$option_url = wp_parse_url( get_option( $option ) );

		if ( ! $option_url || ! $url ) {
			return $url;
		}

		if ( "www.{$option_url[ 'host' ]}" === $url['host'] ) {
			// remove www if not present in option URL.
			$url['host'] = $option_url['host'];
		}
		if ( "www.{$url[ 'host' ]}" === $option_url['host'] ) {
			// add www if present in option URL.
			$url['host'] = $option_url['host'];
		}

		$normalized_url = "{$url['scheme']}://{$url['host']}";
		if ( isset( $url['path'] ) ) {
			$normalized_url .= "{$url['path']}";
		}

		if ( isset( $url['query'] ) ) {
			$normalized_url .= "?{$url['query']}";
		}

		return $normalized_url;
	}

	/**
	 * Return URL with a normalized protocol.
	 *
	 * @param callable $callable Function to retrieve URL option.
	 * @param string   $new_value URL Protocol to set URLs to.
	 * @return string Normalized URL.
	 */
	public static function get_protocol_normalized_url( $callable, $new_value ) {
		$option_key = self::HTTPS_CHECK_OPTION_PREFIX . $callable;

		$parsed_url = wp_parse_url( $new_value );
		if ( ! $parsed_url ) {
			return $new_value;
		}
		if ( array_key_exists( 'scheme', $parsed_url ) ) {
			$scheme = $parsed_url['scheme'];
		} else {
			$scheme = '';
		}
		$scheme_history   = get_option( $option_key, array() );
		$scheme_history[] = $scheme;

		// Limit length to self::HTTPS_CHECK_HISTORY.
		$scheme_history = array_slice( $scheme_history, ( self::HTTPS_CHECK_HISTORY * -1 ) );

		update_option( $option_key, $scheme_history );

		$forced_scheme = in_array( 'https', $scheme_history, true ) ? 'https' : 'http';

		return set_url_scheme( $new_value, $forced_scheme );
	}

	/**
	 * Helper function that is used when getting home or siteurl values. Decides
	 * whether to get the raw or filtered value.
	 *
	 * @param string $url_type URL to get, home or siteurl.
	 * @return string
	 */
	public static function get_raw_or_filtered_url( $url_type ) {
		$url_function = ( 'home' === $url_type )
			? 'home_url'
			: 'site_url';

		if (
			! Constants::is_defined( 'JETPACK_SYNC_USE_RAW_URL' ) ||
			Constants::get_constant( 'JETPACK_SYNC_USE_RAW_URL' )
		) {
			$scheme = is_ssl() ? 'https' : 'http';
			$url    = (string) self::get_raw_url( $url_type );
			$url    = set_url_scheme( $url, $scheme );
		} else {
			$url = self::normalize_www_in_url( $url_type, $url_function );
		}

		return self::get_protocol_normalized_url( $url_function, $url );
	}

	/**
	 * Return the escaped home_url.
	 *
	 * @return string
	 */
	public static function home_url() {
		$url = self::get_raw_or_filtered_url( 'home' );

		/**
		 * Allows overriding of the home_url value that is synced back to WordPress.com.
		 *
		 * @since 1.7.0
		 * @since-jetpack 5.2.0
		 *
		 * @param string $home_url
		 */
		return esc_url_raw( apply_filters( 'jetpack_sync_home_url', $url ) );
	}

	/**
	 * Return the escaped siteurl.
	 *
	 * @return string
	 */
	public static function site_url() {
		$url = self::get_raw_or_filtered_url( 'siteurl' );

		/**
		 * Allows overriding of the site_url value that is synced back to WordPress.com.
		 *
		 * @since 1.7.0
		 * @since-jetpack 5.2.0
		 *
		 * @param string $site_url
		 */
		return esc_url_raw( apply_filters( 'jetpack_sync_site_url', $url ) );
	}

	/**
	 * Return main site URL with a normalized protocol.
	 *
	 * @return string
	 */
	public static function main_network_site_url() {
		return self::get_protocol_normalized_url( 'main_network_site_url', network_site_url() );
	}

}
