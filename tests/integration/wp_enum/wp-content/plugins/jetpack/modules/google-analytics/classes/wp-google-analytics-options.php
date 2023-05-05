<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileNames
/**
 * Jetpack_Google_Analytics_Options provides a single interface to module options
 *
 * @author allendav
 */

/**
 * Bail if accessed directly
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Jetpack_Google_Analytics_Options main class.
 */
class Jetpack_Google_Analytics_Options {
	/**
	 * Get the Google Analytics tracking ID.
	 *
	 * @param string $option_name Nested 'jetpack_wga' option value to retrieve.
	 * @param mixed  $default Default value if $option is not set.
	 * @return mixed Option value or `$default`.
	 */
	public static function get_option( $option_name, $default = false ) {
		$o = get_option( 'jetpack_wga' );
		return isset( $o[ $option_name ] ) ? $o[ $option_name ] : $default;
	}

	/**
	 * Get the analytics tracking code.
	 *
	 * @return string
	 */
	public static function get_tracking_code() {
		return self::get_option( 'code', '' );
	}

	/**
	 * Check if the tracking code is set.
	 *
	 * @return bool
	 */
	public static function has_tracking_code() {
		$code = self::get_tracking_code();
		return ! empty( $code );
	}

	/**
	 * Get the 'anonymize_ip' option used by both legacy and universal analytics.
	 *
	 * @return bool
	 */
	public static function anonymize_ip_is_enabled() {
		return (bool) self::get_option( 'anonymize_ip' );
	}

	/**
	 * Get the 'honor_dnt' option used by both legacy and universal analytics.
	 *
	 * @return bool
	 */
	public static function honor_dnt_is_enabled() {
		return (bool) static::get_option( 'honor_dnt' );
	}

	/**
	 * Get the 'ec_track_purchases' eCommerce option used by both legacy and universal analytics
	 *
	 * @return bool
	 */
	public static function track_purchases_is_enabled() {
		return (bool) self::get_option( 'ec_track_purchases' );
	}

	/**
	 * Get the 'ec_track_add_to_cart' analytics option.
	 *
	 * @return bool
	 */
	public static function track_add_to_cart_is_enabled() {
		return (bool) self::get_option( 'ec_track_add_to_cart' );
	}

	/**
	 * Get the 'enh_ec_tracking' analytics option.
	 *
	 * @return bool
	 */
	public static function enhanced_ecommerce_tracking_is_enabled() {
		return (bool) self::get_option( 'enh_ec_tracking' );
	}

	/**
	 * Get the 'enh_ec_track_remove_from_cart' analytics option.
	 *
	 * @return bool
	 */
	public static function track_remove_from_cart_is_enabled() {
		return (bool) self::get_option( 'enh_ec_track_remove_from_cart' );
	}

	/**
	 * Get the 'enh_ec_track_prod_impression' analytics option.
	 *
	 * @return bool
	 */
	public static function track_product_impressions_is_enabled() {
		return (bool) self::get_option( 'enh_ec_track_prod_impression' );
	}

	/**
	 * Get the 'enh_ec_track_prod_click' analytics option.
	 *
	 * @return bool
	 */
	public static function track_product_clicks_is_enabled() {
		return (bool) self::get_option( 'enh_ec_track_prod_click' );
	}

	/**
	 * Get the 'enh_ec_track_prod_detail_view' analytics option.
	 *
	 * @return bool
	 */
	public static function track_product_detail_view_is_enabled() {
		return (bool) self::get_option( 'enh_ec_track_prod_detail_view' );
	}

	/**
	 * Get the 'enh_ec_track_checkout_started' analytics option.
	 *
	 * @return bool
	 */
	public static function track_checkout_started_is_enabled() {
		return (bool) self::get_option( 'enh_ec_track_checkout_started' );
	}
}
