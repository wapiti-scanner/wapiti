<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Simple Payments lets users embed a PayPal button fully integrated with wpcom to sell products on the site.
 * This is not a proper module yet, because not all the pieces are in place. Until everything is shipped, it can be turned
 * into module that can be enabled/disabled.
 *
 * @package automattic/jetpack
 */

/**
 * Jetpack_Simple_Payments
 */
class Jetpack_Simple_Payments {
	// These have to be under 20 chars because that is CPT limit.

	/**
	 * Post type order.
	 *
	 * @var string
	 */
	public static $post_type_order = 'jp_pay_order';

	/**
	 * Post type product.
	 *
	 * @var string
	 */
	public static $post_type_product = 'jp_pay_product';

	/**
	 * Define simple payment shortcode.
	 *
	 * @var string
	 */
	public static $shortcode = 'simple-payment';

	/**
	 * Define simple payment CSS prefix.
	 *
	 * @var string
	 */
	public static $css_classname_prefix = 'jetpack-simple-payments';

	/**
	 * Which plan the user is on.
	 *
	 * @var string value_bundle or jetpack_premium
	 */
	public static $required_plan;

	/**
	 * Instance of the class.
	 *
	 * @var Jetpack_Simple_Payments
	 */
	private static $instance;

	/**
	 * Construction function.
	 */
	private function __construct() {}

	/**
	 * Original singleton.
	 *
	 * @todo Remove this when nothing calles getInstance anymore.
	 *
	 * @deprecated 10.8
	 */
	public static function getInstance() { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		_deprecated_function( __METHOD__, 'Jetpack 10.7.0', 'Jetpack_Simple_Payments::get_instance' );
		return self::get_instance();
	}

	/**
	 * Create instance of class.
	 */
	public static function get_instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
			self::$instance->register_init_hooks();
			self::$required_plan = ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ? 'value_bundle' : 'jetpack_premium';
		}
		return self::$instance;
	}

	/**
	 * Register scripts and styles.
	 */
	private function register_scripts_and_styles() {
		/**
		 * Paypal heavily discourages putting that script in your own server:
		 *
		 * @see https://developer.paypal.com/docs/integration/direct/express-checkout/integration-jsv4/add-paypal-button/
		 */
		wp_register_script( // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- Ignored here instead of on the $ver param line since wpcom isn't in sync with ruleset changes in: https://github.com/Automattic/jetpack/pull/28199
			'paypal-checkout-js',
			'https://www.paypalobjects.com/api/checkout.js',
			array(),
			null, // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
			true
		);
		wp_register_script(
			'jetpack-paypal-express-checkout',
			plugins_url( '/paypal-express-checkout.js', __FILE__ ),
			array( 'jquery', 'paypal-checkout-js' ),
			JETPACK__VERSION,
			false
		);
		wp_register_style(
			'jetpack-simple-payments',
			plugins_url( '/simple-payments.css', __FILE__ ),
			array( 'dashicons' ),
			JETPACK__VERSION,
			false
		);
	}

	/**
	 * Register init hooks.
	 */
	private function register_init_hooks() {
		add_action( 'init', array( $this, 'init_hook_action' ) );
		add_action( 'rest_api_init', array( $this, 'register_meta_fields_in_rest_api' ) );
	}

	/**
	 * Register the shortcode.
	 */
	private function register_shortcode() {
		add_shortcode( self::$shortcode, array( $this, 'parse_shortcode' ) );
	}

	/**
	 * Actions that are run on init.
	 */
	public function init_hook_action() {
		add_filter( 'rest_api_allowed_post_types', array( $this, 'allow_rest_api_types' ) );
		add_filter( 'jetpack_sync_post_meta_whitelist', array( $this, 'allow_sync_post_meta' ) );
		if ( ! is_admin() ) {
			$this->register_scripts_and_styles();
		}
		$this->register_shortcode();
		$this->setup_cpts();

		add_filter( 'the_content', array( $this, 'remove_auto_paragraph_from_product_description' ), 0 );
	}

	/**
	 * Enqueue the static assets needed in the frontend.
	 */
	public function enqueue_frontend_assets() {
		if ( ! wp_style_is( 'jetpack-simple-payments', 'enqueued' ) ) {
			wp_enqueue_style( 'jetpack-simple-payments' );
		}

		if ( ! wp_script_is( 'jetpack-paypal-express-checkout', 'enqueued' ) ) {
			wp_enqueue_script( 'jetpack-paypal-express-checkout' );
		}
	}

	/**
	 * Add an inline script for setting up the PayPal checkout button.
	 *
	 * @param int     $id Product ID.
	 * @param int     $dom_id ID of the DOM element with the purchase message.
	 * @param boolean $is_multiple Whether multiple items of the same product can be purchased.
	 */
	public function setup_paypal_checkout_button( $id, $dom_id, $is_multiple ) {
		wp_add_inline_script(
			'jetpack-paypal-express-checkout',
			sprintf(
				"try{PaypalExpressCheckout.renderButton( '%d', '%d', '%s', '%d' );}catch(e){}",
				esc_js( $this->get_blog_id() ),
				esc_js( $id ),
				esc_js( $dom_id ),
				esc_js( $is_multiple )
			)
		);
	}

	/**
	 * Remove auto paragraph from product description.
	 *
	 * @param string $content - the content of the post.
	 */
	public function remove_auto_paragraph_from_product_description( $content ) {
		if ( get_post_type() === self::$post_type_product ) {
			remove_filter( 'the_content', 'wpautop' );
		}

		return $content;
	}

	/** Return the blog ID */
	public function get_blog_id() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			return get_current_blog_id();
		}

		return Jetpack_Options::get_option( 'id' );
	}

	/**
	 * Used to check whether Simple Payments are enabled for given site.
	 *
	 * @return bool True if Simple Payments are enabled, false otherwise.
	 */
	public function is_enabled_jetpack_simple_payments() {
		/**
		 * Can be used by plugin authors to disable the conflicting output of Simple Payments.
		 *
		 * @since 6.3.0
		 *
		 * @param bool True if Simple Payments should be disabled, false otherwise.
		 */
		if ( apply_filters( 'jetpack_disable_simple_payments', false ) ) {
			return false;
		}

		return (
			( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || Jetpack::is_connection_ready() ) &&
			Jetpack_Plan::supports( 'simple-payments' )
		);
	}

	/**
	 * Get a WP_Post representation of a product
	 *
	 * @param int $id The ID of the product.
	 *
	 * @return array|false|WP_Post
	 */
	private function get_product( $id ) {
		if ( ! $id ) {
			return false;
		}

		$product = get_post( $id );
		if ( ! $product || is_wp_error( $product ) ) {
			return false;
		}
		if ( $product->post_type !== self::$post_type_product || 'publish' !== $product->post_status ) {
			return false;
		}
		return $product;
	}

	/**
	 * Creates the content from a shortcode
	 *
	 * @param array $attrs Shortcode attributes.
	 * @param mixed $content unused.
	 *
	 * @return string|void
	 */
	public function parse_shortcode( $attrs, $content = false ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( empty( $attrs['id'] ) ) {
			return;
		}
		$product = $this->get_product( $attrs['id'] );
		if ( ! $product ) {
			return;
		}

		// We allow for overriding the presentation labels.
		$data = shortcode_atts(
			array(
				'blog_id'     => $this->get_blog_id(),
				'dom_id'      => uniqid( self::$css_classname_prefix . '-' . $product->ID . '_', true ),
				'class'       => self::$css_classname_prefix . '-' . $product->ID,
				'title'       => get_the_title( $product ),
				'description' => $product->post_content,
				'cta'         => get_post_meta( $product->ID, 'spay_cta', true ),
				'multiple'    => get_post_meta( $product->ID, 'spay_multiple', true ) || '0',
			),
			$attrs
		);

		$data['price'] = $this->format_price(
			get_post_meta( $product->ID, 'spay_price', true ),
			get_post_meta( $product->ID, 'spay_currency', true )
		);

		$data['id'] = $attrs['id'];

		if ( ! $this->is_enabled_jetpack_simple_payments() ) {
			if ( jetpack_is_frontend() ) {
				return $this->output_admin_warning( $data );
			}
			return;
		}

		$this->enqueue_frontend_assets();
		$this->setup_paypal_checkout_button( $attrs['id'], $data['dom_id'], $data['multiple'] );

		return $this->output_shortcode( $data );
	}

	/**
	 * Output an admin warning if user can't use Pay with PayPal.
	 *
	 * @param array $data unused.
	 */
	public function output_admin_warning( $data ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		require_once JETPACK__PLUGIN_DIR . '_inc/lib/components.php';
		return Jetpack_Components::render_upgrade_nudge(
			array(
				'plan' => self::$required_plan,
			)
		);
	}

	/**
	 * Get the HTML output to use as PayPal purchase box.
	 *
	 * @param string  $dom_id ID of the DOM element with the purchase message.
	 * @param boolean $is_multiple Whether multiple items of the same product can be purchased.
	 *
	 * @return string
	 */
	public function output_purchase_box( $dom_id, $is_multiple ) {
		$items      = '';
		$css_prefix = self::$css_classname_prefix;

		if ( $is_multiple ) {
			$items = sprintf(
				'
				<div class="%1$s">
					<input class="%2$s" type="number" value="1" min="1" id="%3$s" />
				</div>
				',
				esc_attr( "{$css_prefix}-items" ),
				esc_attr( "{$css_prefix}-items-number" ),
				esc_attr( "{$dom_id}_number" )
			);
		}

		return sprintf(
			'<div class="%1$s" id="%2$s"></div><div class="%3$s">%4$s<div class="%5$s" id="%6$s"></div></div>',
			esc_attr( "{$css_prefix}-purchase-message" ),
			esc_attr( "{$dom_id}-message-container" ),
			esc_attr( "{$css_prefix}-purchase-box" ),
			$items,
			esc_attr( "{$css_prefix}-button" ),
			esc_attr( "{$dom_id}_button" )
		);
	}

	/**
	 * Get the HTML output to replace the `simple-payments` shortcode.
	 *
	 * @param array $data Product data.
	 * @return string
	 */
	public function output_shortcode( $data ) {
		$css_prefix = self::$css_classname_prefix;

		$image = '';
		if ( has_post_thumbnail( $data['id'] ) ) {
			$image = sprintf(
				'<div class="%1$s"><div class="%2$s">%3$s</div></div>',
				esc_attr( "{$css_prefix}-product-image" ),
				esc_attr( "{$css_prefix}-image" ),
				get_the_post_thumbnail( $data['id'], 'full' )
			);
		}

		return sprintf(
			'
<div class="%1$s">
	<div class="%2$s">
		%3$s
		<div class="%4$s">
			<div class="%5$s"><p>%6$s</p></div>
			<div class="%7$s"><p>%8$s</p></div>
			<div class="%9$s"><p>%10$s</p></div>
			%11$s
		</div>
	</div>
</div>
',
			esc_attr( "{$data['class']} {$css_prefix}-wrapper" ),
			esc_attr( "{$css_prefix}-product" ),
			$image,
			esc_attr( "{$css_prefix}-details" ),
			esc_attr( "{$css_prefix}-title" ),
			esc_html( $data['title'] ),
			esc_attr( "{$css_prefix}-description" ),
			wp_kses( $data['description'], wp_kses_allowed_html( 'post' ) ),
			esc_attr( "{$css_prefix}-price" ),
			esc_html( $data['price'] ),
			$this->output_purchase_box( $data['dom_id'], $data['multiple'] )
		);
	}

	/**
	 * Format a price with currency
	 *
	 * Uses currency-aware formatting to output a formatted price with a simple fallback.
	 *
	 * Largely inspired by WordPress.com's Store_Price::display_currency
	 *
	 * @param  string $price    Price.
	 * @param  string $currency Currency.
	 * @return string           Formatted price.
	 */
	private function format_price( $price, $currency ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/class-jetpack-currencies.php';
		return Jetpack_Currencies::format_price( $price, $currency );
	}

	/**
	 * Allows custom post types to be used by REST API.
	 *
	 * @param array $post_types - the allows post types.
	 * @see hook 'rest_api_allowed_post_types'
	 * @return array
	 */
	public function allow_rest_api_types( $post_types ) {
		$post_types[] = self::$post_type_order;
		$post_types[] = self::$post_type_product;
		return $post_types;
	}

	/**
	 * Merge $post_meta with additional meta information.
	 *
	 * @param array $post_meta - the post's meta information.
	 */
	public function allow_sync_post_meta( $post_meta ) {
		return array_merge(
			$post_meta,
			array(
				'spay_paypal_id',
				'spay_status',
				'spay_product_id',
				'spay_quantity',
				'spay_price',
				'spay_customer_email',
				'spay_currency',
				'spay_cta',
				'spay_email',
				'spay_multiple',
				'spay_formatted_price',
			)
		);
	}

	/**
	 * Enable Simple payments custom meta values for access through the REST API.
	 * Field’s value will be exposed on a .meta key in the endpoint response,
	 * and WordPress will handle setting up the callbacks for reading and writing
	 * to that meta key.
	 *
	 * @link https://developer.wordpress.org/rest-api/extending-the-rest-api/modifying-responses/
	 */
	public function register_meta_fields_in_rest_api() {
		register_meta(
			'post',
			'spay_price',
			array(
				'description'       => esc_html__( 'Simple payments; price.', 'jetpack' ),
				'object_subtype'    => self::$post_type_product,
				'sanitize_callback' => array( $this, 'sanitize_price' ),
				'show_in_rest'      => true,
				'single'            => true,
				'type'              => 'number',
			)
		);

		register_meta(
			'post',
			'spay_currency',
			array(
				'description'       => esc_html__( 'Simple payments; currency code.', 'jetpack' ),
				'object_subtype'    => self::$post_type_product,
				'sanitize_callback' => array( $this, 'sanitize_currency' ),
				'show_in_rest'      => true,
				'single'            => true,
				'type'              => 'string',
			)
		);

		register_meta(
			'post',
			'spay_cta',
			array(
				'description'       => esc_html__( 'Simple payments; text with "Buy" or other CTA', 'jetpack' ),
				'object_subtype'    => self::$post_type_product,
				'sanitize_callback' => 'sanitize_text_field',
				'show_in_rest'      => true,
				'single'            => true,
				'type'              => 'string',
			)
		);

		register_meta(
			'post',
			'spay_multiple',
			array(
				'description'       => esc_html__( 'Simple payments; allow multiple items', 'jetpack' ),
				'object_subtype'    => self::$post_type_product,
				'sanitize_callback' => 'rest_sanitize_boolean',
				'show_in_rest'      => true,
				'single'            => true,
				'type'              => 'boolean',
			)
		);

		register_meta(
			'post',
			'spay_email',
			array(
				'description'       => esc_html__( 'Simple payments button; paypal email.', 'jetpack' ),
				'object_subtype'    => self::$post_type_product,
				'sanitize_callback' => 'sanitize_email',
				'show_in_rest'      => true,
				'single'            => true,
				'type'              => 'string',
			)
		);

		register_meta(
			'post',
			'spay_status',
			array(
				'description'       => esc_html__( 'Simple payments; status.', 'jetpack' ),
				'object_subtype'    => self::$post_type_product,
				'sanitize_callback' => 'sanitize_text_field',
				'show_in_rest'      => true,
				'single'            => true,
				'type'              => 'string',
			)
		);
	}

	/**
	 * Sanitize three-character ISO-4217 Simple payments currency
	 *
	 * List has to be in sync with list at the block's client side and widget's backend side:
	 *
	 * @param array $currency - list of currencies.
	 * @link https://github.com/Automattic/jetpack/blob/31efa189ad223c0eb7ad085ac0650a23facf9ef5/extensions/blocks/simple-payments/constants.js#L9-L39
	 * @link https://github.com/Automattic/jetpack/blob/31efa189ad223c0eb7ad085ac0650a23facf9ef5/modules/widgets/simple-payments.php#L19-L44
	 *
	 * Currencies should be supported by PayPal:
	 * @link https://developer.paypal.com/docs/api/reference/currency-codes/
	 *
	 * Indian Rupee (INR) not supported because at the time of the creation of this file
	 * because it's limited to in-country PayPal India accounts only.
	 * Discussion: https://github.com/Automattic/wp-calypso/pull/28236
	 */
	public static function sanitize_currency( $currency ) {
		$valid_currencies = array(
			'USD',
			'EUR',
			'AUD',
			'BRL',
			'CAD',
			'CZK',
			'DKK',
			'HKD',
			'HUF',
			'ILS',
			'JPY',
			'MYR',
			'MXN',
			'TWD',
			'NZD',
			'NOK',
			'PHP',
			'PLN',
			'GBP',
			'RUB',
			'SGD',
			'SEK',
			'CHF',
			'THB',
		);

		return in_array( $currency, $valid_currencies, true ) ? $currency : false;
	}

	/**
	 * Sanitize price:
	 *
	 * Positive integers and floats
	 * Supports two decimal places.
	 * Maximum length: 10.
	 *
	 * See `price` from PayPal docs:
	 *
	 * @link https://developer.paypal.com/docs/api/orders/v1/#definition-item
	 *
	 * @param string $price - the price we want to sanitize.
	 * @return null|string
	 */
	public static function sanitize_price( $price ) {
		return preg_match( '/^[0-9]{0,10}(\.[0-9]{0,2})?$/', $price ) ? $price : false;
	}

	/**
	 * Sets up the custom post types for the module.
	 */
	public function setup_cpts() {
		/*
		 * ORDER data structure. holds:
		 * title = customer_name | 4xproduct_name
		 * excerpt = customer_name + customer contact info + customer notes from paypal form
		 * metadata:
		 * spay_paypal_id - paypal id of transaction
		 * spay_status
		 * spay_product_id - post_id of bought product
		 * spay_quantity - quantity of product
		 * spay_price - item price at the time of purchase
		 * spay_customer_email - customer email
		 * ... (WIP)
		 */
		$order_capabilities = array(
			'edit_post'          => 'edit_posts',
			'read_post'          => 'read_private_posts',
			'delete_post'        => 'delete_posts',
			'edit_posts'         => 'edit_posts',
			'edit_others_posts'  => 'edit_others_posts',
			'publish_posts'      => 'publish_posts',
			'read_private_posts' => 'read_private_posts',
		);
		$order_args         = array(
			'label'               => esc_html_x( 'Order', 'noun: a quantity of goods or items purchased or sold', 'jetpack' ),
			'description'         => esc_html__( 'Simple Payments orders', 'jetpack' ),
			'supports'            => array( 'custom-fields', 'excerpt' ),
			'hierarchical'        => false,
			'public'              => false,
			'show_ui'             => false,
			'show_in_menu'        => false,
			'show_in_admin_bar'   => false,
			'show_in_nav_menus'   => false,
			'can_export'          => true,
			'has_archive'         => false,
			'exclude_from_search' => true,
			'publicly_queryable'  => false,
			'rewrite'             => false,
			'capabilities'        => $order_capabilities,
			'show_in_rest'        => true,
		);
		register_post_type( self::$post_type_order, $order_args );

		/*
		 * PRODUCT data structure. Holds:
		 * title - title
		 * content - description
		 * thumbnail - image
		 * metadata:
		 * spay_price - price
		 * spay_formatted_price
		 * spay_currency - currency code
		 * spay_cta - text with "Buy" or other CTA
		 * spay_email - paypal email
		 * spay_multiple - allow for multiple items
		 * spay_status - status. { enabled | disabled }
		 */
		$product_capabilities = array(
			'edit_post'          => 'edit_posts',
			'read_post'          => 'read_private_posts',
			'delete_post'        => 'delete_posts',
			'edit_posts'         => 'publish_posts',
			'edit_others_posts'  => 'edit_others_posts',
			'publish_posts'      => 'publish_posts',
			'read_private_posts' => 'read_private_posts',
		);
		$product_args         = array(
			'label'               => esc_html__( 'Product', 'jetpack' ),
			'description'         => esc_html__( 'Simple Payments products', 'jetpack' ),
			'supports'            => array( 'title', 'editor', 'thumbnail', 'custom-fields', 'author' ),
			'hierarchical'        => false,
			'public'              => false,
			'show_ui'             => false,
			'show_in_menu'        => false,
			'show_in_admin_bar'   => false,
			'show_in_nav_menus'   => false,
			'can_export'          => true,
			'has_archive'         => false,
			'exclude_from_search' => true,
			'publicly_queryable'  => false,
			'rewrite'             => false,
			'capabilities'        => $product_capabilities,
			'show_in_rest'        => true,
		);
		register_post_type( self::$post_type_product, $product_args );
	}

	/**
	 * Validate the block attributes
	 *
	 * @param array $attrs The block attributes, expected to contain:
	 *                      * email - an email address.
	 *                      * price - a float between 0.01 and 9999999999.99.
	 *                      * productId - the ID of the product being paid for.
	 *
	 * @return bool
	 */
	public function is_valid( $attrs ) {
		if ( ! $this->validate_paypal_email( $attrs ) ) {
			return false;
		}

		if ( ! $this->validate_price( $attrs ) ) {
			return false;
		}

		if ( ! $this->validate_product( $attrs ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check that the email address to make a payment to is valid
	 *
	 * @param array $attrs Key-value array of attributes.
	 *
	 * @return boolean
	 */
	private function validate_paypal_email( $attrs ) {
		if ( empty( $attrs['email'] ) ) {
			return false;
		}
		return (bool) filter_var( $attrs['email'], FILTER_VALIDATE_EMAIL );
	}

	/**
	 * Check that the price is valid
	 *
	 * @param array $attrs Key-value array of attributes.
	 *
	 * @return bool
	 */
	private function validate_price( $attrs ) {
		if ( empty( $attrs['price'] ) ) {
			return false;
		}
		return (bool) self::sanitize_price( $attrs['price'] );
	}

	/**
	 * Check that the stored product is valid
	 *
	 * Valid means it has a title, and the currency is accepted.
	 *
	 * @param array $attrs Key-value array of attributes.
	 *
	 * @return bool
	 */
	private function validate_product( $attrs ) {
		if ( empty( $attrs['productId'] ) ) {
			return false;
		}
		$product = $this->get_product( $attrs['productId'] );
		if ( ! $product ) {
			return false;
		}
		// This title is the one used by paypal, it's set from the title set in the block content, unless the block
		// content title is blank.
		if ( ! get_the_title( $product ) ) {
			return false;
		}

		$currency = get_post_meta( $product->ID, 'spay_currency', true );
		return (bool) self::sanitize_currency( $currency );
	}

	/**
	 * Format a price for display
	 *
	 * Largely taken from WordPress.com Store_Price class
	 *
	 * The currency array will have the shape:
	 *   format  => string sprintf format with placeholders `%1$s`: Symbol `%2$s`: Price.
	 *   symbol  => string Symbol string
	 *   desc    => string Text description of currency
	 *   decimal => int    Number of decimal places
	 *
	 * @param  string $the_currency The desired currency, e.g. 'USD'.
	 * @return ?array               Currency object or null if not found.
	 */
	private static function get_currency( $the_currency ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/class-jetpack-currencies.php';
		$currencies = Jetpack_Currencies::CURRENCIES;

		if ( isset( $currencies[ $the_currency ] ) ) {
			return $currencies[ $the_currency ];
		}
		return null;
	}
}
Jetpack_Simple_Payments::get_instance();
