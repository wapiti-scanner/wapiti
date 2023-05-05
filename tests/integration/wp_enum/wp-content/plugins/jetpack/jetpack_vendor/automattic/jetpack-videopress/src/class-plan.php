<?php
/**
 * The Plan class.
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * The Plan class.
 */
class Plan {
	/**
	 * The meta name used to store the cache date
	 *
	 * @var string
	 */
	const CACHE_DATE_META_NAME = 'videopress-cache-date';

	/**
	 * Valid pediord for the cache: One week.
	 */
	const CACHE_VALIDITY_PERIOD = 7 * DAY_IN_SECONDS;

	/**
	 * The meta name used to store the cache
	 *
	 * @var string
	 */
	const CACHE_META_NAME = 'videopress-cache';

	/**
	 * Checks if the cache is old, meaning we need to fetch new data from WPCOM
	 */
	private static function is_cache_old() {
		if ( empty( self::get_product_from_cache() ) ) {
			return true;
		}

		$cache_date = get_user_meta( get_current_user_id(), self::CACHE_DATE_META_NAME, true );
		return time() - (int) $cache_date > ( self::CACHE_VALIDITY_PERIOD );
	}

	/**
	 * Gets the product list from the user cache
	 */
	private static function get_product_from_cache() {
		return get_user_meta( get_current_user_id(), self::CACHE_META_NAME, true );
	}

	/**
	 * Gets the product data
	 *
	 * @return array
	 */
	public static function get_product() {
		$request_url   = 'https://public-api.wordpress.com/rest/v1.1/products?locale=' . get_user_locale() . '&type=jetpack';
		$wpcom_request = wp_remote_get( esc_url_raw( $request_url ) );
		$response_code = wp_remote_retrieve_response_code( $wpcom_request );

		if ( 200 === $response_code ) {
			$products = json_decode( wp_remote_retrieve_body( $wpcom_request ) );
			if ( ! isset( $products->jetpack_videopress ) || ! isset( $products->jetpack_videopress_monthly ) ) {
				return array();
			}

			// Pick the desired product...
			$product = $products->jetpack_videopress;

			// ... and store it into the cache.
			update_user_meta( get_current_user_id(), self::CACHE_DATE_META_NAME, time() );
			update_user_meta( get_current_user_id(), self::CACHE_META_NAME, $product );

			return $product;
		}

		return new \WP_Error(
			'failed_to_fetch_data',
			esc_html__( 'Unable to fetch the requested data.', 'jetpack-videopress-pkg' ),
			array(
				'status'  => $response_code,
				'request' => $wpcom_request,
			)
		);
	}

	/**
	 * Populate the pricing array with the discount information.
	 *
	 * @param {object} $product - The product object.
	 * @return {integer} Discount percentage.
	 */
	public static function get_coupon_discount( $product ) {
		// Check whether the product has a coupon.
		if ( ! isset( $product->sale_coupon ) ) {
			return false;
		}

		$product_id = $product->product_id;
		$coupon     = $product->sale_coupon;

		// Check product is covered by the coupon.
		if ( ! in_array( $product_id, $coupon->product_ids, true ) ) {
			return false;
		}

		// Check whether it is still valid.
		$coupon_start_date = strtotime( $coupon->start_date );
		$coupon_expires    = strtotime( $coupon->expires );
		if ( $coupon_start_date > time() || $coupon_expires < time() ) {
			return false;
		}

		if ( ! isset( $coupon->discount ) ) {
			return false;
		}

		return intval( $coupon->discount );
	}

	/**
	 * Return details about the VideoPress product price
	 *
	 * @return array Produce price details
	 */
	public static function get_product_price() {
		$request_url   = 'https://public-api.wordpress.com/rest/v1.1/products?locale=' . get_user_locale() . '&type=jetpack';
		$wpcom_request = wp_remote_get( esc_url_raw( $request_url ) );
		$response_code = wp_remote_retrieve_response_code( $wpcom_request );

		if ( 200 === $response_code ) {
			$products = json_decode( wp_remote_retrieve_body( $wpcom_request ) );

			$products_list = array();

			if ( isset( $products->jetpack_videopress ) ) {
				$videopress_yearly = $products->jetpack_videopress;
				// get_coupon_discount
				$products_list['yearly'] = array(
					'name'         => $videopress_yearly->product_name,
					'slug'         => $videopress_yearly->product_slug,
					'price'        => $videopress_yearly->cost,
					'priceByMonth' => round( $videopress_yearly->cost / 12, 2 ),
					'currency'     => $videopress_yearly->currency_code,
				);

				$discount = self::get_coupon_discount( $videopress_yearly );

				if ( $discount ) {
					$products_list['yearly']['discount']         = $discount;
					$products_list['yearly']['salePrice']        = round( $videopress_yearly->cost * ( 1 - $discount / 100 ), 2 );
					$products_list['yearly']['salePriceByMonth'] = round( ( $videopress_yearly->cost * ( 1 - $discount / 100 ) / 12 ), 2 );
				} else {
					$products_list['yearly']['salePrice']        = $videopress_yearly->cost;
					$products_list['yearly']['salePriceByMonth'] = round( $videopress_yearly->cost / 12, 2 );
				}
			}

			if ( isset( $products->jetpack_videopress_monthly ) ) {
				$videopress_monthly = $products->jetpack_videopress_monthly;

				$products_list['monthly'] = array(
					'name'     => $videopress_monthly->product_name,
					'slug'     => $videopress_monthly->product_slug,
					'price'    => $videopress_monthly->cost,
					'currency' => $videopress_monthly->currency_code,
				);
			}

			return $products_list;
		}

		return new \WP_Error(
			'failed_to_fetch_data',
			esc_html__( 'Unable to fetch the requested data.', 'jetpack-videopress-pkg' ),
			array(
				'status'  => $response_code,
				'request' => $wpcom_request,
			)
		);
	}
}
