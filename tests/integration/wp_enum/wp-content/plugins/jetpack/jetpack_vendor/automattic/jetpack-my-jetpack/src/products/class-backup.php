<?php
/**
 * Boost product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\My_Jetpack\Hybrid_Product;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;
use Automattic\Jetpack\Redirect;
use Jetpack_Options;
use WP_Error;

/**
 * Class responsible for handling the Backup product
 */
class Backup extends Hybrid_Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'backup';

	/**
	 * The filename (id) of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_filename = array(
		'jetpack-backup/jetpack-backup.php',
		'backup/jetpack-backup.php',
		'jetpack-backup-dev/jetpack-backup.php',
	);

	/**
	 * The slug of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_slug = 'jetpack-backup';

	/**
	 * Backup has a standalone plugin
	 *
	 * @var bool
	 */
	public static $has_standalone_plugin = true;

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return __( 'VaultPress Backup', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack VaultPress Backup', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Save every change', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'Never lose a word, image, page, or time worrying about your site with automated backups & one-click restores.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Backup features list
	 */
	public static function get_features() {
		return array(
			_x( 'Real-time cloud backups', 'Backup Product Feature', 'jetpack-my-jetpack' ),
			_x( '10GB of backup storage', 'Backup Product Feature', 'jetpack-my-jetpack' ),
			_x( '30-day archive & activity log*', 'Backup Product Feature', 'jetpack-my-jetpack' ),
			_x( 'One-click restores', 'Backup Product Feature', 'jetpack-my-jetpack' ),
		);
	}

	/**
	 * Get disclaimers corresponding to a feature
	 *
	 * @return array Backup disclaimers list
	 */
	public static function get_disclaimers() {
		return array(
			array(
				'text'      => _x( '* Subject to your usage and storage limit.', 'Backup Product Disclaimer', 'jetpack-my-jetpack' ),
				'link_text' => _x( 'Learn more', 'Backup Product Disclaimer', 'jetpack-my-jetpack' ),
				'url'       => Redirect::get_url( 'jetpack-faq-backup-disclaimer' ),
			),
		);
	}

	/**
	 * Get the WPCOM product slug used to make the purchase
	 *
	 * @return ?string
	 */
	public static function get_wpcom_product_slug() {
		return 'jetpack_backup_t1_yearly';
	}

	/**
	 * Get the product princing details
	 *
	 * @return array Pricing details
	 */
	public static function get_pricing_for_ui() {
		return array_merge(
			array(
				'available'          => true,
				'wpcom_product_slug' => static::get_wpcom_product_slug(),
			),
			Wpcom_Products::get_product_pricing( static::get_wpcom_product_slug() )
		);
	}

	/**
	 * Hits the wpcom api to check rewind status.
	 *
	 * @todo Maybe add caching.
	 *
	 * @return Object|WP_Error
	 */
	private static function get_state_from_wpcom() {
		static $status = null;

		if ( $status !== null ) {
			return $status;
		}

		$site_id = Jetpack_Options::get_option( 'id' );

		$response = Client::wpcom_json_api_request_as_blog( sprintf( '/sites/%d/rewind', $site_id ) . '?force=wpcom', '2', array( 'timeout' => 2 ), null, 'wpcom' );

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'rewind_state_fetch_failed' );
		}

		$body   = wp_remote_retrieve_body( $response );
		$status = json_decode( $body );
		return $status;
	}

	/**
	 * Checks whether the current plan (or purchases) of the site already supports the product
	 *
	 * @return boolean
	 */
	public static function has_required_plan() {
		$rewind_data = static::get_state_from_wpcom();
		if ( is_wp_error( $rewind_data ) ) {
			return false;
		}
		return is_object( $rewind_data ) && isset( $rewind_data->state ) && 'unavailable' !== $rewind_data->state;
	}

	/**
	 * Return product bundles list
	 * that supports the product.
	 *
	 * @return boolean|array Products bundle list.
	 */
	public static function is_upgradable_by_bundle() {
		return array( 'security' );
	}

	/**
	 * Get the URL the user is taken after activating the product
	 *
	 * @return ?string
	 */
	public static function get_post_activation_url() {
		return ''; // stay in My Jetpack page or continue the purchase flow if needed.
	}

	/**
	 * Get the URL where the user manages the product
	 *
	 * @return ?string
	 */
	public static function get_manage_url() {
		if ( static::is_jetpack_plugin_active() ) {
			return Redirect::get_url( 'my-jetpack-manage-backup' );
		} elseif ( static::is_plugin_active() ) {
			return admin_url( 'admin.php?page=jetpack-backup' );
		}
	}

	/**
	 * Checks whether the Product is active
	 *
	 * @return boolean
	 */
	public static function is_active() {
		return parent::is_active() && static::has_required_plan();
	}

	/**
	 * Get the URL where the user should be redirected after checkout
	 */
	public static function get_post_checkout_url() {
		if ( static::is_jetpack_plugin_active() ) {
			return admin_url( 'admin.php?page=jetpack#/recommendations' );
		} elseif ( static::is_plugin_active() ) {
			return admin_url( 'admin.php?page=jetpack-backup' );
		}
	}
}
