<?php
/**
 * Class for the Jetpack partner coupon logic.
 *
 * @package automattic/jetpack-partner
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Connection\Client as Connection_Client;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Jetpack_Options;

/**
 * Disable direct access.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jetpack_Partner_Coupon
 *
 * @since 1.6.0
 */
class Partner_Coupon {

	/**
	 * Name of the Jetpack_Option coupon option.
	 *
	 * @var string
	 */
	public static $coupon_option = 'partner_coupon';

	/**
	 * Name of the Jetpack_Option added option.
	 *
	 * @var string
	 */
	public static $added_option = 'partner_coupon_added';

	/**
	 * Name of "last availability check" transient.
	 *
	 * @var string
	 */
	public static $last_check_transient = 'jetpack_partner_coupon_last_check';

	/**
	 * Callable that executes a blog-authenticated request.
	 *
	 * @var callable
	 */
	protected $request_as_blog;

	/**
	 * Jetpack_Partner_Coupon
	 *
	 * @var Partner_Coupon|null
	 **/
	private static $instance = null;

	/**
	 * A list of supported partners.
	 *
	 * @var array
	 */
	private static $supported_partners = array(
		'IONOS' => array(
			'name' => 'IONOS',
			'logo' => array(
				'src'    => '/images/ionos-logo.jpg',
				'width'  => 119,
				'height' => 32,
			),
		),
	);

	/**
	 * A list of supported presets.
	 *
	 * @var array
	 */
	private static $supported_presets = array(
		'IONA' => 'jetpack_backup_daily',
	);

	/**
	 * Get singleton instance of class.
	 *
	 * @return Partner_Coupon
	 */
	public static function get_instance() {
		if ( self::$instance === null ) {
			self::$instance = new Partner_Coupon( array( Connection_Client::class, 'wpcom_json_api_request_as_blog' ) );
		}

		return self::$instance;
	}

	/**
	 * Constructor.
	 *
	 * @param callable $request_as_blog Callable that executes a blog-authenticated request.
	 */
	public function __construct( $request_as_blog ) {
		$this->request_as_blog = $request_as_blog;
	}

	/**
	 * Register hooks to catch and purge coupon.
	 *
	 * @param string $plugin_slug The plugin slug to differentiate between Jetpack connections.
	 * @param string $redirect_location The location we should redirect to after catching the coupon.
	 */
	public static function register_coupon_admin_hooks( $plugin_slug, $redirect_location ) {
		$instance = self::get_instance();

		// We have to use an anonymous function, so we can pass along relevant information
		// and not have to hardcode values for a single plugin.
		// This open up the opportunity for e.g. the "all-in-one" and backup plugins
		// to both implement partner coupon logic.
		add_action(
			'admin_init',
			function () use ( $plugin_slug, $redirect_location, $instance ) {
				$instance->catch_coupon( $plugin_slug, $redirect_location );
				$instance->maybe_purge_coupon( $plugin_slug );
			}
		);
	}

	/**
	 * Catch partner coupon and redirect to claim component.
	 *
	 * @param string $plugin_slug The plugin slug to differentiate between Jetpack connections.
	 * @param string $redirect_location The location we should redirect to after catching the coupon.
	 */
	public function catch_coupon( $plugin_slug, $redirect_location ) {
		// Accept and store a partner coupon if present, and redirect to Jetpack connection screen.
		$partner_coupon = isset( $_GET['jetpack-partner-coupon'] ) ? sanitize_text_field( wp_unslash( $_GET['jetpack-partner-coupon'] ) ) : false; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $partner_coupon ) {
			Jetpack_Options::update_options(
				array(
					self::$coupon_option => $partner_coupon,
					self::$added_option  => time(),
				)
			);

			$connection = new Connection_Manager( $plugin_slug );
			if ( $connection->is_connected() ) {
				$redirect_location = add_query_arg( array( 'showCouponRedemption' => 1 ), $redirect_location );
				wp_safe_redirect( $redirect_location );
			} else {
				wp_safe_redirect( $redirect_location );
			}
		}
	}

	/**
	 * Purge partner coupon.
	 *
	 * We try to remotely check if a coupon looks valid. We also automatically purge
	 * partner coupons after a certain amount of time to prevent unnecessary look-ups
	 * and/or promoting a product for months or years in the future due to unknown
	 * errors.
	 *
	 * @param string $plugin_slug The plugin slug to differentiate between Jetpack connections.
	 */
	public function maybe_purge_coupon( $plugin_slug ) {
		// Only run coupon checks on Jetpack admin pages.
		// The "admin-ui" package is responsible for registering the Jetpack admin
		// page for all Jetpack plugins and has hardcoded the settings page to be
		// "jetpack", so we shouldn't need to allow for dynamic/custom values.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['page'] ) || 'jetpack' !== $_GET['page'] ) {
			return;
		}

		if ( ( new Status() )->is_offline_mode() ) {
			return;
		}

		$connection = new Connection_Manager( $plugin_slug );
		if ( ! $connection->is_connected() ) {
			return;
		}

		if ( $this->maybe_purge_coupon_by_added_date() ) {
			return;
		}

		// Limit checks to happen once a minute at most.
		if ( get_transient( self::$last_check_transient ) ) {
			return;
		}

		set_transient( self::$last_check_transient, true, MINUTE_IN_SECONDS );

		$this->maybe_purge_coupon_by_availability_check();
	}

	/**
	 * Purge coupon based on local added date.
	 *
	 * We automatically remove the coupon after a month to "self-heal" if
	 * something in the claim process has broken with the site.
	 *
	 * @return bool Return whether we should skip further purge checks.
	 */
	protected function maybe_purge_coupon_by_added_date() {
		$date = Jetpack_Options::get_option( self::$added_option, '' );

		if ( empty( $date ) ) {
			return true;
		}

		$expire_date = strtotime( '+30 days', $date );
		$today       = time();

		if ( $today >= $expire_date ) {
			$this->delete_coupon_data();

			return true;
		}

		return false;
	}

	/**
	 * Purge coupon based on availability check.
	 *
	 * @return bool Return whether we deleted coupon data.
	 */
	protected function maybe_purge_coupon_by_availability_check() {
		$blog_id = Jetpack_Options::get_option( 'id', false );

		if ( ! $blog_id ) {
			return false;
		}

		$coupon = self::get_coupon();

		if ( ! $coupon ) {
			return false;
		}

		$response = call_user_func_array(
			$this->request_as_blog,
			array(
				add_query_arg(
					array( 'coupon_code' => $coupon['coupon_code'] ),
					sprintf(
						'/sites/%d/jetpack-partner/coupon/v1/site/coupon',
						$blog_id
					)
				),
				2,
				array( 'method' => 'GET' ),
				null,
				'wpcom',
			)
		);

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if (
			200 === wp_remote_retrieve_response_code( $response ) &&
			is_array( $body ) &&
			isset( $body['available'] ) &&
			false === $body['available']
		) {
			$this->delete_coupon_data();

			return true;
		}

		return false;
	}

	/**
	 * Delete all coupon data.
	 */
	protected function delete_coupon_data() {
		Jetpack_Options::delete_option(
			array(
				self::$coupon_option,
				self::$added_option,
			)
		);
	}

	/**
	 * Get partner coupon data.
	 *
	 * @return array|bool
	 */
	public static function get_coupon() {
		$coupon_code = Jetpack_Options::get_option( self::$coupon_option, '' );

		if ( ! is_string( $coupon_code ) || empty( $coupon_code ) ) {
			return false;
		}

		$instance = self::get_instance();
		$partner  = $instance->get_coupon_partner( $coupon_code );

		if ( ! $partner ) {
			return false;
		}

		$preset = $instance->get_coupon_preset( $coupon_code );

		if ( ! $preset ) {
			return false;
		}

		$product = $instance->get_coupon_product( $preset );

		if ( ! $product ) {
			return false;
		}

		return array(
			'coupon_code' => $coupon_code,
			'partner'     => $partner,
			'preset'      => $preset,
			'product'     => $product,
		);
	}

	/**
	 * Get coupon partner.
	 *
	 * @param string $coupon_code Coupon code to go through.
	 * @return array|bool
	 */
	private function get_coupon_partner( $coupon_code ) {
		if ( ! is_string( $coupon_code ) || false === strpos( $coupon_code, '_' ) ) {
			return false;
		}

		$prefix             = strtok( $coupon_code, '_' );
		$supported_partners = $this->get_supported_partners();

		if ( ! isset( $supported_partners[ $prefix ] ) ) {
			return false;
		}

		return array(
			'name'   => $supported_partners[ $prefix ]['name'],
			'prefix' => $prefix,
			'logo'   => isset( $supported_partners[ $prefix ]['logo'] ) ? $supported_partners[ $prefix ]['logo'] : null,
		);
	}

	/**
	 * Get coupon product.
	 *
	 * @param string $coupon_preset The preset we wish to find a product for.
	 * @return array|bool
	 */
	private function get_coupon_product( $coupon_preset ) {
		if ( ! is_string( $coupon_preset ) ) {
			return false;
		}

		/**
		 * Allow for plugins to register supported products.
		 *
		 * @since 1.6.0
		 *
		 * @param array A list of product details.
		 * @return array
		 */
		$product_details = apply_filters( 'jetpack_partner_coupon_products', array() );
		$product_slug    = $this->get_supported_presets()[ $coupon_preset ];

		foreach ( $product_details as $product ) {
			if ( ! $this->array_keys_exist( array( 'title', 'slug', 'description', 'features' ), $product ) ) {
				continue;
			}

			if ( $product_slug === $product['slug'] ) {
				return $product;
			}
		}

		return false;
	}

	/**
	 * Checks if multiple keys are present in an array.
	 *
	 * @param array $needles The keys we wish to check for.
	 * @param array $haystack The array we want to compare keys against.
	 *
	 * @return bool
	 */
	private function array_keys_exist( $needles, $haystack ) {
		foreach ( $needles as $needle ) {
			if ( ! isset( $haystack[ $needle ] ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get coupon preset.
	 *
	 * @param string $coupon_code Coupon code to go through.
	 * @return string|bool
	 */
	private function get_coupon_preset( $coupon_code ) {
		if ( ! is_string( $coupon_code ) ) {
			return false;
		}

		$regex   = '/^.*?_(?P<slug>.*?)_.+$/';
		$matches = array();

		if ( ! preg_match( $regex, $coupon_code, $matches ) ) {
			return false;
		}

		return isset( $this->get_supported_presets()[ $matches['slug'] ] ) ? $matches['slug'] : false;
	}

	/**
	 * Get supported partners.
	 *
	 * @return array
	 */
	private function get_supported_partners() {
		/**
		 * Allow external code to add additional supported partners.
		 *
		 * @since 1.6.0
		 *
		 * @param array $supported_partners A list of supported partners.
		 * @return array
		 */
		return apply_filters( 'jetpack_partner_coupon_supported_partners', self::$supported_partners );
	}

	/**
	 * Get supported presets.
	 *
	 * @return array
	 */
	private function get_supported_presets() {
		/**
		 * Allow external code to add additional supported presets.
		 *
		 * @since 1.6.0
		 *
		 * @param array $supported_presets A list of supported presets.
		 * @return array
		 */
		return apply_filters( 'jetpack_partner_coupon_supported_presets', self::$supported_presets );
	}

}
