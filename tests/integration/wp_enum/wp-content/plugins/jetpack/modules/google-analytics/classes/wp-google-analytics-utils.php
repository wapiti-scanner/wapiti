<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
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
 * Jetpack_Google_Analytics_Utils main class.
 */
class Jetpack_Google_Analytics_Utils {
	/**
	 * Gets product categories or varation attributes as a formatted concatenated string
	 *
	 * @param WC_Product $product Product to get categories/variations for.
	 * @return string
	 */
	public static function get_product_categories_concatenated( $product ) {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return '';
		}

		if ( ! $product ) {
			return '';
		}

		$variation_data = $product->is_type( 'variation' ) ? wc_get_product_variation_attributes( $product->get_id() ) : '';
		if ( is_array( $variation_data ) && ! empty( $variation_data ) ) {
			$line = wc_get_formatted_variation( $variation_data, true );
		} else {
			$out        = array();
			$categories = get_the_terms( $product->get_id(), 'product_cat' );
			if ( $categories ) {
				foreach ( $categories as $category ) {
					$out[] = $category->name;
				}
			}
			$line = join( '/', $out );
		}
		return $line;
	}

	/**
	 * Gets a product's SKU with fallback to just ID. IDs are prepended with a hash symbol.
	 *
	 * @param WC_Product $product Product to get SKU/ID for.
	 * @return string
	 */
	public static function get_product_sku_or_id( $product ) {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return '';
		}

		if ( ! $product ) {
			return '';
		}

		return $product->get_sku() ? $product->get_sku() : '#' . $product->get_id();
	}

	/**
	 * Checks if filter is set and dnt is enabled.
	 *
	 * @return bool
	 */
	public static function is_dnt_enabled() {
		/**
		 * Filter the option which decides honor DNT or not.
		 *
		 * @module google-analytics
		 * @since 11.3
		 *
		 * @param bool $honor_dnt Honors DNT for clients who don't want to be tracked. Set to true to enable.
		 */
		if ( false === apply_filters( 'jetpack_honor_dnt_header_for_wga', Jetpack_Google_Analytics_Options::honor_dnt_is_enabled() ) ) {
			return false;
		}

		foreach ( $_SERVER as $name => $value ) {
			if ( 'http_dnt' === strtolower( $name ) && 1 === (int) $value ) {
				return true;
			}
		}

		return false;
	}
}
