<?php
/**
 * Add support for Google Analytics e-commerce events for AMP pages.
 *
 * @package automattic/jetpack
 */

/**
 * Bail if accessed directly
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Jetpack_Google_AMP_Analytics class.
 */
class Jetpack_Google_AMP_Analytics {
	/**
	 * Constructor method.
	 */
	public function __construct() {
		$this->maybe_load_hooks();
	}

	/**
	 * Maybe load the hooks.
	 * Checks if its AMP request, if WooCommerce is available, if DNT is disabled, if there's tracking code and if tracking is enabled.
	 */
	public function maybe_load_hooks() {
		if ( ! class_exists( 'Jetpack_AMP_Support' ) || ! Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		if ( ! class_exists( 'WooCommerce' ) ) {
			return;
		}

		if ( ! Jetpack_Google_Analytics_Options::has_tracking_code() ) {
			return;
		}

		if ( Jetpack_Google_Analytics_Utils::is_dnt_enabled() ) {
			return;
		}

		if ( ! Jetpack_Google_Analytics_Options::track_add_to_cart_is_enabled() ) {
			return;
		}

		add_action( 'woocommerce_add_to_cart', array( $this, 'amp_add_to_cart' ), 10, 6 );
		add_action( 'woocommerce_thankyou', array( $this, 'amp_after_purchase' ), 10, 1 );
		add_action( 'wp_footer', array( $this, 'amp_send_ga_events' ) );
	}

	/**
	 * Generate a GA event when adding an item to the cart.
	 *
	 * @param string $cart_item_key Cart item key.
	 * @param string $product_id Product ID.
	 * @param int    $quantity Product quantity.
	 * @param int    $variation_id Product variation ID.
	 * @param object $variation Product variation.
	 * @param object $cart_item_data Cart item data.
	 */
	public function amp_add_to_cart( $cart_item_key, $product_id, $quantity, $variation_id, $variation, $cart_item_data ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$product = wc_get_product( $product_id );
		if ( $product ) {
			$product_sku  = Jetpack_Google_Analytics_Utils::get_product_sku_or_id( $product );
			$product_name = $product->get_name();

			$events   = WC()->session->get( 'wc_ga_events' );
			$events[] = array(
				'type'      => 'add',
				'ga_params' => array(
					'pa'    => 'add',
					'pr1id' => sanitize_text_field( $product_sku ),
					'pr1nm' => sanitize_text_field( $product_name ),
					'pr1qt' => absint( $quantity ),
				),
			);
			WC()->session->set( 'wc_ga_events', $events );
		}
	}

	/**
	 * Generate a GA event when removing an item to the cart.
	 *
	 * @param int $order_id The Order ID.
	 */
	public function amp_after_purchase( $order_id ) {
		$events      = WC()->session->get( 'wc_ga_events' );
		$order       = wc_get_order( $order_id );
		$order_total = $order->get_total();
		$order_tax   = $order->get_total_tax();

		$i     = 1;
		$event = array(
			'type'      => 'purchase',
			'ga_params' => array(
				'pa' => 'purchase',
				'ti' => absint( $order_id ),
				'tr' => (float) $order_total,
				'tt' => (float) $order_tax,
			),
		);
		foreach ( $order->get_items() as $item ) {
			$product = $item->get_product();
			if ( $product ) {
				$event['ga_params'][ 'pr' . $i . 'id' ] = sanitize_text_field( Jetpack_Google_Analytics_Utils::get_product_sku_or_id( $product ) );
				$event['ga_params'][ 'pr' . $i . 'nm' ] = sanitize_text_field( $item->get_name() );
				$event['ga_params'][ 'pr' . $i . 'qt' ] = absint( $item->get_quantity() );
				++$i;
			}
		}

		$events[] = $event;
		WC()->session->set( 'wc_ga_events', $events );
	}

	/**
	 * Send the stored events to GA.
	 */
	public function amp_send_ga_events() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'GET' !== strtoupper( $_SERVER['REQUEST_METHOD'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Simple comparison
			return;
		}

		$events = WC()->session->get( 'wc_ga_events' );
		if ( ! is_array( $events ) ) {
			return;
		}

		foreach ( $events as $event ) {
			?>
			<amp-analytics type='googleanalytics'>
				<script type='application/json'>
				{
					"vars": {
						"account": "<?php echo esc_html( Jetpack_Google_Analytics_Options::get_tracking_code() ); ?>"
					},
					"triggers": {
						"trackPageview": {
							"on": "visible",
							"request": "pageview",
							"extraUrlParams": <?php echo wp_json_encode( $event['ga_params'] ); ?>
						}
					}
				}
				</script>
			</amp-analytics>
			<?php

			array_shift( $events );
		}
		WC()->session->set( 'wc_ga_events', $events );
	}
}
