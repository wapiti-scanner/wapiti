<?php
/**
 * WooCommerce sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use WP_Error;

/**
 * Class to handle sync for WooCommerce.
 */
class WooCommerce extends Module {
	/**
	 * Whitelist for order item meta we are interested to sync.
	 *
	 * @access private
	 *
	 * @var array
	 */
	public static $order_item_meta_whitelist = array(
		// See https://github.com/woocommerce/woocommerce/blob/master/includes/data-stores/class-wc-order-item-product-store.php#L20 .
		'_product_id',
		'_variation_id',
		'_qty',
		// Tax ones also included in below class
		// See https://github.com/woocommerce/woocommerce/blob/master/includes/data-stores/class-wc-order-item-fee-data-store.php#L20 .
		'_tax_class',
		'_tax_status',
		'_line_subtotal',
		'_line_subtotal_tax',
		'_line_total',
		'_line_tax',
		'_line_tax_data',
		// See https://github.com/woocommerce/woocommerce/blob/master/includes/data-stores/class-wc-order-item-shipping-data-store.php#L20 .
		'method_id',
		'cost',
		'total_tax',
		'taxes',
		// See https://github.com/woocommerce/woocommerce/blob/master/includes/data-stores/class-wc-order-item-tax-data-store.php#L20 .
		'rate_id',
		'label',
		'compound',
		'tax_amount',
		'shipping_tax_amount',
		// See https://github.com/woocommerce/woocommerce/blob/master/includes/data-stores/class-wc-order-item-coupon-data-store.php .
		'discount_amount',
		'discount_amount_tax',
	);

	/**
	 * Name of the order item database table.
	 *
	 * @access private
	 *
	 * @var string
	 */
	private $order_item_table_name;

	/**
	 * The table in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function table_name() {
		return $this->order_item_table_name;
	}

	/**
	 * Constructor.
	 *
	 * @global $wpdb
	 *
	 * @todo Should we refactor this to use $this->set_defaults() instead?
	 */
	public function __construct() {
		global $wpdb;
		$this->order_item_table_name = $wpdb->prefix . 'woocommerce_order_items';

		// Options, constants and post meta whitelists.
		add_filter( 'jetpack_sync_options_whitelist', array( $this, 'add_woocommerce_options_whitelist' ), 10 );
		add_filter( 'jetpack_sync_constants_whitelist', array( $this, 'add_woocommerce_constants_whitelist' ), 10 );
		add_filter( 'jetpack_sync_post_meta_whitelist', array( $this, 'add_woocommerce_post_meta_whitelist' ), 10 );
		add_filter( 'jetpack_sync_comment_meta_whitelist', array( $this, 'add_woocommerce_comment_meta_whitelist' ), 10 );

		add_filter( 'jetpack_sync_before_enqueue_woocommerce_new_order_item', array( $this, 'filter_order_item' ) );
		add_filter( 'jetpack_sync_before_enqueue_woocommerce_update_order_item', array( $this, 'filter_order_item' ) );
		add_filter( 'jetpack_sync_whitelisted_comment_types', array( $this, 'add_review_comment_types' ) );

		// Blacklist Action Scheduler comment types.
		add_filter( 'jetpack_sync_prevent_sending_comment_data', array( $this, 'filter_action_scheduler_comments' ), 10, 2 );
	}

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'woocommerce';
	}

	/**
	 * Initialize WooCommerce action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		// Attributes.
		add_action( 'woocommerce_attribute_added', $callable, 10, 2 );
		add_action( 'woocommerce_attribute_updated', $callable, 10, 3 );
		add_action( 'woocommerce_attribute_deleted', $callable, 10, 3 );

		// Orders.
		add_action( 'woocommerce_new_order', $callable, 10, 1 );
		add_action( 'woocommerce_order_status_changed', $callable, 10, 3 );
		add_action( 'woocommerce_payment_complete', $callable, 10, 1 );

		// Order items.
		add_action( 'woocommerce_new_order_item', $callable, 10, 4 );
		add_action( 'woocommerce_update_order_item', $callable, 10, 4 );
		add_action( 'woocommerce_delete_order_item', $callable, 10, 1 );
		$this->init_listeners_for_meta_type( 'order_item', $callable );

		// Payment tokens.
		add_action( 'woocommerce_new_payment_token', $callable, 10, 1 );
		add_action( 'woocommerce_payment_token_deleted', $callable, 10, 2 );
		add_action( 'woocommerce_payment_token_updated', $callable, 10, 1 );
		$this->init_listeners_for_meta_type( 'payment_token', $callable );

		// Product downloads.
		add_action( 'woocommerce_downloadable_product_download_log_insert', $callable, 10, 1 );
		add_action( 'woocommerce_grant_product_download_access', $callable, 10, 1 );

		// Tax rates.
		add_action( 'woocommerce_tax_rate_added', $callable, 10, 2 );
		add_action( 'woocommerce_tax_rate_updated', $callable, 10, 2 );
		add_action( 'woocommerce_tax_rate_deleted', $callable, 10, 1 );

		// Webhooks.
		add_action( 'woocommerce_new_webhook', $callable, 10, 1 );
		add_action( 'woocommerce_webhook_deleted', $callable, 10, 2 );
		add_action( 'woocommerce_webhook_updated', $callable, 10, 1 );
	}

	/**
	 * Initialize WooCommerce action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_woocommerce_order_items', $callable ); // Also sends post meta.
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_woocommerce_order_items' );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		// Full sync.
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_woocommerce_order_items', array( $this, 'expand_order_item_ids' ) );
	}

	/**
	 * Expand the order items properly.
	 *
	 * @access public
	 *
	 * @param array $args The hook arguments.
	 * @return array $args The hook arguments.
	 */
	public function filter_order_item( $args ) {
		// Make sure we always have all the data - prior to WooCommerce 3.0 we only have the user supplied data in the second argument and not the full details.
		$args[1] = $this->build_order_item( $args[0] );
		return $args;
	}

	/**
	 * Expand order item IDs to order items and their meta.
	 *
	 * @access public
	 *
	 * @todo Refactor table name to use a $wpdb->prepare placeholder.
	 *
	 * @param array $args The hook arguments.
	 * @return array $args Expanded order items with meta.
	 */
	public function expand_order_item_ids( $args ) {
		$order_item_ids = $args[0];

		global $wpdb;

		$order_item_ids_sql = implode( ', ', array_map( 'intval', $order_item_ids ) );

		$order_items = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT * FROM $this->order_item_table_name WHERE order_item_id IN ( $order_item_ids_sql )"
		);

		return array(
			$order_items,
			$this->get_metadata( $order_item_ids, 'order_item', static::$order_item_meta_whitelist ),
		);
	}

	/**
	 * Extract the full order item from the database by its ID.
	 *
	 * @access public
	 *
	 * @todo Refactor table name to use a $wpdb->prepare placeholder.
	 *
	 * @param int $order_item_id Order item ID.
	 * @return object Order item.
	 */
	public function build_order_item( $order_item_id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $this->order_item_table_name WHERE order_item_id = %d", $order_item_id ) );
	}

	/**
	 * Enqueue the WooCommerce actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config               Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state                True if full sync has finished enqueueing this module, false otherwise.
	 * @return array Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) {
		return $this->enqueue_all_ids_as_action( 'jetpack_full_sync_woocommerce_order_items', $this->order_item_table_name, 'order_item_id', $this->get_where_sql( $config ), $max_items_to_enqueue, $state );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @todo Refactor the SQL query to use $wpdb->prepare().
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return array Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) {
		global $wpdb;

		$query = "SELECT count(*) FROM $this->order_item_table_name WHERE " . $this->get_where_sql( $config );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$count = $wpdb->get_var( $query );

		return (int) ceil( $count / self::ARRAY_CHUNK_SIZE );
	}

	/**
	 * Retrieve the WHERE SQL clause based on the module config.
	 *
	 * @access private
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return string WHERE SQL clause.
	 */
	public function get_where_sql( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return '1=1';
	}

	/**
	 * Add WooCommerce options to the options whitelist.
	 *
	 * @param array $list Existing options whitelist.
	 * @return array Updated options whitelist.
	 */
	public function add_woocommerce_options_whitelist( $list ) {
		return array_merge( $list, self::$wc_options_whitelist );
	}

	/**
	 * Add WooCommerce constants to the constants whitelist.
	 *
	 * @param array $list Existing constants whitelist.
	 * @return array Updated constants whitelist.
	 */
	public function add_woocommerce_constants_whitelist( $list ) {
		return array_merge( $list, self::$wc_constants_whitelist );
	}

	/**
	 * Add WooCommerce post meta to the post meta whitelist.
	 *
	 * @param array $list Existing post meta whitelist.
	 * @return array Updated post meta whitelist.
	 */
	public function add_woocommerce_post_meta_whitelist( $list ) {
		return array_merge( $list, self::$wc_post_meta_whitelist );
	}

	/**
	 * Add WooCommerce comment meta to the comment meta whitelist.
	 *
	 * @param array $list Existing comment meta whitelist.
	 * @return array Updated comment meta whitelist.
	 */
	public function add_woocommerce_comment_meta_whitelist( $list ) {
		return array_merge( $list, self::$wc_comment_meta_whitelist );
	}

	/**
	 * Adds 'revew' to the list of comment types so Sync will listen for status changes on 'reviews'.
	 *
	 * @access public
	 *
	 * @param array $comment_types The list of comment types prior to this filter.
	 * return array                The list of comment types with 'review' added.
	 */
	public function add_review_comment_types( $comment_types ) {
		if ( is_array( $comment_types ) ) {
			$comment_types[] = 'review';
		}
		return $comment_types;
	}

	/**
	 * Stop comments from the Action Scheduler from being synced.
	 * https://github.com/woocommerce/woocommerce/tree/e7762627c37ec1f7590e6cac4218ba0c6a20024d/includes/libraries/action-scheduler
	 *
	 * @since 1.6.3
	 * @since-jetpack 7.7.0
	 *
	 * @param boolean $can_sync Should we prevent comment data from bing synced to WordPress.com.
	 * @param mixed   $comment  WP_COMMENT object.
	 *
	 * @return bool
	 */
	public function filter_action_scheduler_comments( $can_sync, $comment ) {
		if ( isset( $comment->comment_agent ) && 'ActionScheduler' === $comment->comment_agent ) {
			return true;
		}
		return $can_sync;
	}

	/**
	 * Whitelist for options we are interested to sync.
	 *
	 * @access private
	 * @static
	 *
	 * @var array
	 */
	private static $wc_options_whitelist = array(
		'woocommerce_currency',
		'woocommerce_db_version',
		'woocommerce_weight_unit',
		'woocommerce_version',
		'woocommerce_unforce_ssl_checkout',
		'woocommerce_tax_total_display',
		'woocommerce_tax_round_at_subtotal',
		'woocommerce_tax_display_shop',
		'woocommerce_tax_display_cart',
		'woocommerce_prices_include_tax',
		'woocommerce_price_thousand_sep',
		'woocommerce_price_num_decimals',
		'woocommerce_price_decimal_sep',
		'woocommerce_notify_low_stock',
		'woocommerce_notify_low_stock_amount',
		'woocommerce_notify_no_stock',
		'woocommerce_notify_no_stock_amount',
		'woocommerce_manage_stock',
		'woocommerce_force_ssl_checkout',
		'woocommerce_hide_out_of_stock_items',
		'woocommerce_file_download_method',
		'woocommerce_enable_signup_and_login_from_checkout',
		'woocommerce_enable_shipping_calc',
		'woocommerce_enable_review_rating',
		'woocommerce_enable_guest_checkout',
		'woocommerce_enable_coupons',
		'woocommerce_enable_checkout_login_reminder',
		'woocommerce_enable_ajax_add_to_cart',
		'woocommerce_dimension_unit',
		'woocommerce_default_country',
		'woocommerce_default_customer_address',
		'woocommerce_currency_pos',
		'woocommerce_api_enabled',
		'woocommerce_allow_tracking',
		'woocommerce_task_list_hidden',
		'woocommerce_onboarding_profile',
		'woocommerce_cod_settings',
	);

	/**
	 * Whitelist for constants we are interested to sync.
	 *
	 * @access private
	 * @static
	 *
	 * @var array
	 */
	private static $wc_constants_whitelist = array(
		// WooCommerce constants.
		'WC_PLUGIN_FILE',
		'WC_ABSPATH',
		'WC_PLUGIN_BASENAME',
		'WC_VERSION',
		'WOOCOMMERCE_VERSION',
		'WC_ROUNDING_PRECISION',
		'WC_DISCOUNT_ROUNDING_MODE',
		'WC_TAX_ROUNDING_MODE',
		'WC_DELIMITER',
		'WC_LOG_DIR',
		'WC_SESSION_CACHE_GROUP',
		'WC_TEMPLATE_DEBUG_MODE',
	);

	/**
	 * Whitelist for post meta we are interested to sync.
	 *
	 * @access private
	 * @static
	 *
	 * @var array
	 */
	private static $wc_post_meta_whitelist = array(
		// WooCommerce products.
		// See https://github.com/woocommerce/woocommerce/blob/8ed6e7436ff87c2153ed30edd83c1ab8abbdd3e9/includes/data-stores/class-wc-product-data-store-cpt.php#L21 .
		'_visibility',
		'_sku',
		'_price',
		'_regular_price',
		'_sale_price',
		'_sale_price_dates_from',
		'_sale_price_dates_to',
		'total_sales',
		'_tax_status',
		'_tax_class',
		'_manage_stock',
		'_backorders',
		'_sold_individually',
		'_weight',
		'_length',
		'_width',
		'_height',
		'_upsell_ids',
		'_crosssell_ids',
		'_purchase_note',
		'_default_attributes',
		'_product_attributes',
		'_virtual',
		'_downloadable',
		'_download_limit',
		'_download_expiry',
		'_featured',
		'_downloadable_files',
		'_wc_rating_count',
		'_wc_average_rating',
		'_wc_review_count',
		'_variation_description',
		'_thumbnail_id',
		'_file_paths',
		'_product_image_gallery',
		'_product_version',
		'_wp_old_slug',

		// Woocommerce orders.
		// See https://github.com/woocommerce/woocommerce/blob/8ed6e7436ff87c2153ed30edd83c1ab8abbdd3e9/includes/data-stores/class-wc-order-data-store-cpt.php#L27 .
		'_order_key',
		'_order_currency',
		// '_billing_first_name', do not sync these as they contain personal data
		// '_billing_last_name',
		// '_billing_company',
		// '_billing_address_1',
		// '_billing_address_2',
		'_billing_city',
		'_billing_state',
		'_billing_postcode',
		'_billing_country',
		// '_billing_email', do not sync these as they contain personal data.
		// '_billing_phone',
		// '_shipping_first_name',
		// '_shipping_last_name',
		// '_shipping_company',
		// '_shipping_address_1',
		// '_shipping_address_2',
		'_shipping_city',
		'_shipping_state',
		'_shipping_postcode',
		'_shipping_country',
		'_completed_date',
		'_paid_date',
		'_cart_discount',
		'_cart_discount_tax',
		'_order_shipping',
		'_order_shipping_tax',
		'_order_tax',
		'_order_total',
		'_payment_method',
		'_payment_method_title',
		// '_transaction_id', do not sync these as they contain personal data.
		// '_customer_ip_address',
		// '_customer_user_agent',
		'_created_via',
		'_order_version',
		'_prices_include_tax',
		'_date_completed',
		'_date_paid',
		'_payment_tokens',
		'_billing_address_index',
		'_shipping_address_index',
		'_recorded_sales',
		'_recorded_coupon_usage_counts',
		// See https://github.com/woocommerce/woocommerce/blob/8ed6e7436ff87c2153ed30edd83c1ab8abbdd3e9/includes/data-stores/class-wc-order-data-store-cpt.php#L539 .
		'_download_permissions_granted',
		// See https://github.com/woocommerce/woocommerce/blob/8ed6e7436ff87c2153ed30edd83c1ab8abbdd3e9/includes/data-stores/class-wc-order-data-store-cpt.php#L594 .
		'_order_stock_reduced',

		// Woocommerce order refunds.
		// See https://github.com/woocommerce/woocommerce/blob/b8a2815ae546c836467008739e7ff5150cb08e93/includes/data-stores/class-wc-order-refund-data-store-cpt.php#L20 .
		'_order_currency',
		'_refund_amount',
		'_refunded_by',
		'_refund_reason',
		'_order_shipping',
		'_order_shipping_tax',
		'_order_tax',
		'_order_total',
		'_order_version',
		'_prices_include_tax',
		'_payment_tokens',
	);

	/**
	 * Whitelist for comment meta we are interested to sync.
	 *
	 * @access private
	 * @static
	 *
	 * @var array
	 */
	private static $wc_comment_meta_whitelist = array(
		'rating',
	);

	/**
	 * Return a list of objects by their type and IDs
	 *
	 * @param string $object_type Object type.
	 * @param array  $ids IDs of objects to return.
	 *
	 * @access public
	 *
	 * @return array|object|WP_Error|null
	 */
	public function get_objects_by_id( $object_type, $ids ) {
		switch ( $object_type ) {
			case 'order_item':
				return $this->get_order_item_by_ids( $ids );
		}

		return new WP_Error( 'unsupported_object_type', 'Unsupported object type' );
	}

	/**
	 * Returns a list of order_item objects by their IDs.
	 *
	 * @param array $ids List of order_item IDs to fetch.
	 *
	 * @access public
	 *
	 * @return array|object|null
	 */
	public function get_order_item_by_ids( $ids ) {
		global $wpdb;

		if ( ! is_array( $ids ) ) {
			return array();
		}

		// Make sure the IDs are numeric and are non-zero.
		$ids = array_filter( array_map( 'intval', $ids ) );

		if ( empty( $ids ) ) {
			return array();
		}

		// Prepare the placeholders for the prepared query below.
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

		$query = "SELECT * FROM {$this->order_item_table_name} WHERE order_item_id IN ( $placeholders )";

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		return $wpdb->get_results( $wpdb->prepare( $query, $ids ), ARRAY_A );
	}
}
