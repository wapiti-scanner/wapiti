<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Tracking;

/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Jetpack_Simple_Payments_Widget' ) ) {
	/**
	 * Pay with PayPal (aka Simple Payments)
	 *
	 * Display a Pay with PayPal button as a Widget.
	 */
	class Jetpack_Simple_Payments_Widget extends WP_Widget {
		/**
		 * Currencies should be supported by PayPal:
		 *
		 * @var array $supported_currency_list
		 * @link https://developer.paypal.com/docs/api/reference/currency-codes/
		 *
		 * List has to be in sync with list at the block's client side and API's backend side:
		 * @link https://github.com/Automattic/jetpack/blob/31efa189ad223c0eb7ad085ac0650a23facf9ef5/extensions/blocks/simple-payments/constants.js#L9-L39
		 * @link https://github.com/Automattic/jetpack/blob/31efa189ad223c0eb7ad085ac0650a23facf9ef5/modules/simple-payments/simple-payments.php#L386-L415
		 *
		 * Indian Rupee (INR) is listed here for backwards compatibility with previously added widgets.
		 * It's not supported by Pay with PayPal because at the time of the creation of this file
		 * because it's limited to in-country PayPal India accounts only.
		 * Discussion: https://github.com/Automattic/wp-calypso/pull/28236
		 */
		private static $supported_currency_list = array(
			'USD' => '$',
			'GBP' => '&#163;',
			'JPY' => '&#165;',
			'BRL' => 'R$',
			'EUR' => '&#8364;',
			'NZD' => 'NZ$',
			'AUD' => 'A$',
			'CAD' => 'C$',
			'INR' => '₹',
			'ILS' => '₪',
			'RUB' => '₽',
			'MXN' => 'MX$',
			'SEK' => 'Skr',
			'HUF' => 'Ft',
			'CHF' => 'CHF',
			'CZK' => 'Kč',
			'DKK' => 'Dkr',
			'HKD' => 'HK$',
			'NOK' => 'Kr',
			'PHP' => '₱',
			'PLN' => 'PLN',
			'SGD' => 'S$',
			'TWD' => 'NT$',
			'THB' => '฿',
		);

		/**
		 * Constructor.
		 */
		public function __construct() {
			parent::__construct(
				'jetpack_simple_payments_widget',
				/** This filter is documented in modules/widgets/facebook-likebox.php */
				apply_filters( 'jetpack_widget_name', __( 'Pay with PayPal', 'jetpack' ) ),
				array(
					'classname'                   => 'jetpack-simple-payments',
					'description'                 => __( 'Add a Pay with PayPal button as a Widget.', 'jetpack' ),
					'customize_selective_refresh' => true,
				)
			);

			global $pagenow;
			if ( is_customize_preview() || 'widgets.php' === $pagenow ) {
				add_action( 'admin_enqueue_scripts', array( $this, 'admin_enqueue_styles' ) );
			}

			$jetpack_simple_payments = Jetpack_Simple_Payments::get_instance();
			if ( is_customize_preview() && $jetpack_simple_payments->is_enabled_jetpack_simple_payments() ) {
				add_action( 'admin_enqueue_scripts', array( $this, 'admin_enqueue_scripts' ) );

				add_filter( 'customize_refresh_nonces', array( $this, 'filter_nonces' ) );
				add_action( 'wp_ajax_customize-jetpack-simple-payments-buttons-get', array( $this, 'ajax_get_payment_buttons' ) );
				add_action( 'wp_ajax_customize-jetpack-simple-payments-button-save', array( $this, 'ajax_save_payment_button' ) );
				add_action( 'wp_ajax_customize-jetpack-simple-payments-button-delete', array( $this, 'ajax_delete_payment_button' ) );
			}

			if ( is_active_widget( false, false, $this->id_base ) || is_customize_preview() ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
			}

			add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_simple_payment_widget' ) );
		}

		/**
		 * Return an array of the widgets hidden from the Legacy Widget block.
		 *
		 * This is used to hide the Pay with PayPal from the Legacy Widget block.
		 *
		 * @param array $widget_types the widget types that are currently hidden.
		 * @return array Widget types hidden from the Legacy Widget block
		 */
		public function hide_simple_payment_widget( $widget_types ) {
			$widget_types[] = 'jetpack_simple_payments_widget';
			return $widget_types;
		}

		/**
		 * Return an associative array of default values.
		 *
		 * These values are used in new widgets.
		 *
		 * @return array Default values for the widget options.
		 */
		private function defaults() {
			$current_user       = wp_get_current_user();
			$default_product_id = $this->get_first_product_id();

			return array(
				'title'                    => '',
				'product_post_id'          => $default_product_id,
				'form_action'              => '',
				'form_product_id'          => 0,
				'form_product_title'       => '',
				'form_product_description' => '',
				'form_product_image_id'    => 0,
				'form_product_image_src'   => '',
				'form_product_currency'    => '',
				'form_product_price'       => '',
				'form_product_multiple'    => '',
				'form_product_email'       => $current_user->user_email,
			);
		}

		/**
		 * Adds a nonce for customizing menus.
		 *
		 * @param array $nonces Array of nonces.
		 * @return array $nonces Modified array of nonces.
		 */
		public function filter_nonces( $nonces ) {
			$nonces['customize-jetpack-simple-payments'] = wp_create_nonce( 'customize-jetpack-simple-payments' );
			return $nonces;
		}

		/**
		 * Enqueue styles.
		 */
		public function enqueue_style() {
			wp_enqueue_style( 'jetpack-simple-payments-widget-style', plugins_url( 'simple-payments/style.css', __FILE__ ), array(), '20180518' );
		}

		/**
		 * Enqueue admin styles.
		 */
		public function admin_enqueue_styles() {
			wp_enqueue_style(
				'jetpack-simple-payments-widget-customizer',
				plugins_url( 'simple-payments/customizer.css', __FILE__ ),
				array(),
				JETPACK__VERSION
			);
		}

		/**
		 * Enqueue admin scripts.
		 */
		public function admin_enqueue_scripts() {
				wp_enqueue_media();
				wp_enqueue_script(
					'jetpack-simple-payments-widget-customizer',
					plugins_url( '/simple-payments/customizer.js', __FILE__ ),
					array( 'jquery' ),
					JETPACK__VERSION,
					true
				);
				wp_localize_script(
					'jetpack-simple-payments-widget-customizer',
					'jpSimplePaymentsStrings',
					array(
						'deleteConfirmation' => __( 'Are you sure you want to delete this item? It will be disabled and removed from all locations where it currently appears.', 'jetpack' ),
					)
				);
		}

		/**
		 * Get payment buttons.
		 */
		public function ajax_get_payment_buttons() {
			if ( ! check_ajax_referer( 'customize-jetpack-simple-payments', 'customize-jetpack-simple-payments-nonce', false ) ) {
				wp_send_json_error( 'bad_nonce', 400 );
			}

			if ( ! current_user_can( 'customize' ) ) {
				wp_send_json_error( 'customize_not_allowed', 403 );
			}

			$post_type_object = get_post_type_object( Jetpack_Simple_Payments::$post_type_product );
			if ( ! current_user_can( $post_type_object->cap->create_posts ) || ! current_user_can( $post_type_object->cap->publish_posts ) ) {
				wp_send_json_error( 'insufficient_post_permissions', 403 );
			}

			$product_posts = get_posts(
				array(
					'numberposts' => 100,
					'orderby'     => 'date',
					'post_type'   => Jetpack_Simple_Payments::$post_type_product,
					'post_status' => 'publish',
				)
			);

			$formatted_products = array_map( array( $this, 'format_product_post_for_ajax_reponse' ), $product_posts );

			wp_send_json_success( $formatted_products );
		}

		/**
		 * Format product_post object.
		 *
		 * @param object $product_post - info about the post the product is on.
		 */
		public function format_product_post_for_ajax_reponse( $product_post ) {
			return array(
				'ID'         => $product_post->ID,
				'post_title' => $product_post->post_title,
			);
		}

		/**
		 * Handle saving the simple payments widget.
		 */
		public function ajax_save_payment_button() {
			if ( ! check_ajax_referer( 'customize-jetpack-simple-payments', 'customize-jetpack-simple-payments-nonce', false ) ) {
				wp_send_json_error( 'bad_nonce', 400 );
			}

			if ( ! current_user_can( 'customize' ) ) {
				wp_send_json_error( 'customize_not_allowed', 403 );
			}

			$post_type_object = get_post_type_object( Jetpack_Simple_Payments::$post_type_product );
			if ( ! current_user_can( $post_type_object->cap->create_posts ) || ! current_user_can( $post_type_object->cap->publish_posts ) ) {
				wp_send_json_error( 'insufficient_post_permissions', 403 );
			}

			if ( empty( $_POST['params'] ) || ! is_array( $_POST['params'] ) ) {
				wp_send_json_error( 'missing_params', 400 );
			}

			$params = wp_unslash( $_POST['params'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Manually validated by validate_ajax_params().
			$errors = $this->validate_ajax_params( $params );
			if ( ! empty( $errors->errors ) ) {
				wp_send_json_error( $errors );
			}

			$product_post_id = isset( $params['product_post_id'] ) ? (int) $params['product_post_id'] : 0;

			$product_post = array(
				'ID'            => $product_post_id,
				'post_type'     => Jetpack_Simple_Payments::$post_type_product,
				'post_status'   => 'publish',
				'post_title'    => $params['post_title'],
				'post_content'  => $params['post_content'],
				'_thumbnail_id' => ! empty( $params['image_id'] ) ? $params['image_id'] : -1,
				'meta_input'    => array(
					'spay_currency' => $params['currency'],
					'spay_price'    => $params['price'],
					'spay_multiple' => isset( $params['multiple'] ) ? (int) $params['multiple'] : 0,
					'spay_email'    => is_email( $params['email'] ),
				),
			);

			if ( empty( $product_post_id ) ) {
				$product_post_id = wp_insert_post( $product_post );
			} else {
				$product_post_id = wp_update_post( $product_post );
			}

			if ( ! $product_post_id || is_wp_error( $product_post_id ) ) {
				wp_send_json_error( $product_post_id );
			}

			$tracks_properties = array(
				'id'       => $product_post_id,
				'currency' => $params['currency'],
				'price'    => $params['price'],
			);
			if ( 0 === $product_post['ID'] ) {
				$this->record_event( 'created', 'create', $tracks_properties );
			} else {
				$this->record_event( 'updated', 'update', $tracks_properties );
			}

			wp_send_json_success(
				array(
					'product_post_id'    => $product_post_id,
					'product_post_title' => $params['post_title'],
				)
			);
		}

		/**
		 * Handle deleting the simple payment widget.
		 */
		public function ajax_delete_payment_button() {
			if ( ! check_ajax_referer( 'customize-jetpack-simple-payments', 'customize-jetpack-simple-payments-nonce', false ) ) {
				wp_send_json_error( 'bad_nonce', 400 );
			}

			if ( ! current_user_can( 'customize' ) ) {
				wp_send_json_error( 'customize_not_allowed', 403 );
			}

			if ( empty( $_POST['params'] ) || ! is_array( $_POST['params'] ) ) {
				wp_send_json_error( 'missing_params', 400 );
			}

			$params         = wp_unslash( $_POST['params'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Manually validated just below.
			$illegal_params = array_diff( array_keys( $params ), array( 'product_post_id' ) );
			if ( ! empty( $illegal_params ) ) {
				wp_send_json_error( 'illegal_params', 400 );
			}

			$product_id   = (int) $params['product_post_id'];
			$product_post = get_post( $product_id );

			$return = array( 'status' => $product_post->post_status );

			wp_delete_post( $product_id, true );
			$status = get_post_status( $product_id );
			if ( false === $status ) {
				$return['status'] = 'deleted';
			}

			$this->record_event( 'deleted', 'delete', array( 'id' => $product_id ) );

			wp_send_json_success( $return );
		}

		/**
		 * Returns the number of decimal places on string representing a price.
		 *
		 * @param string $number Price to check.
		 * @return number number of decimal places.
		 */
		private function get_decimal_places( $number ) {
			$parts = explode( '.', $number );
			if ( count( $parts ) > 2 ) {
				return null;
			}

			return isset( $parts[1] ) ? strlen( $parts[1] ) : 0;
		}

		/**
		 * Validate ajax parameters.
		 *
		 * @param array $params - the parameters.
		 */
		public function validate_ajax_params( $params ) {
			$errors = new WP_Error();

			$illegal_params = array_diff( array_keys( $params ), array( 'product_post_id', 'post_title', 'post_content', 'image_id', 'currency', 'price', 'multiple', 'email' ) );
			if ( ! empty( $illegal_params ) ) {
				$errors->add( 'illegal_params', __( 'Invalid parameters.', 'jetpack' ) );
			}

			if ( empty( $params['post_title'] ) ) {
				$errors->add( 'post_title', __( "People need to know what they're paying for! Please add a brief title.", 'jetpack' ) );
			}

			if ( empty( $params['price'] ) || ! is_numeric( $params['price'] ) || (float) $params['price'] <= 0 ) {
				$errors->add( 'price', __( 'Everything comes with a price tag these days. Please add a your product price.', 'jetpack' ) );
			}

			// Japan's Yen is the only supported currency with a zero decimal precision.
			$precision            = strtoupper( $params['currency'] ) === 'JPY' ? 0 : 2;
			$price_decimal_places = $this->get_decimal_places( $params['price'] );
			if ( $price_decimal_places === null || $price_decimal_places > $precision ) {
				$errors->add( 'price', __( 'Invalid price', 'jetpack' ) );
			}

			if ( empty( $params['email'] ) || ! is_email( $params['email'] ) ) {
				$errors->add( 'email', __( 'We want to make sure payments reach you, so please add an email address.', 'jetpack' ) );
			}

			return $errors;
		}

		/**
		 * Get the id of the first product.
		 */
		public function get_first_product_id() {
			$product_posts = get_posts(
				array(
					'numberposts' => 1,
					'orderby'     => 'date',
					'post_type'   => Jetpack_Simple_Payments::$post_type_product,
					'post_status' => 'publish',
				)
			);

			return ! empty( $product_posts ) ? $product_posts[0]->ID : null;
		}

		/**
		 * Front-end display of widget.
		 *
		 * @see WP_Widget::widget()
		 *
		 * @param array $args     Widget arguments.
		 * @param array $instance Saved values from database.
		 */
		public function widget( $args, $instance ) {
			$instance = wp_parse_args( $instance, $this->defaults() );

			echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			/** This filter is documented in core/src/wp-includes/default-widgets.php */
			$title = apply_filters( 'widget_title', $instance['title'] );
			if ( ! empty( $title ) ) {
				echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}

			echo '<div class="jetpack-simple-payments-content">';

			if ( ! empty( $instance['form_action'] ) && in_array( $instance['form_action'], array( 'add', 'edit' ), true ) && is_customize_preview() ) {
				require __DIR__ . '/simple-payments/widget.php';
			} else {
				$jsp                    = Jetpack_Simple_Payments::get_instance();
				$simple_payments_button = $jsp->parse_shortcode(
					array(
						'id' => $instance['product_post_id'],
					)
				);

				if ( $simple_payments_button !== null || is_customize_preview() ) {
					echo $simple_payments_button; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				}
			}

			echo '</div><!--simple-payments-->';

			echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			/** This action is already documented in modules/widgets/gravatar-profile.php */
			do_action( 'jetpack_stats_extra', 'widget_view', 'simple_payments' );
		}

		/**
		 * Gets the latests field value from either the old instance or the new instance.
		 *
		 * @param array $new_instance mixed Array of values for the new form instance.
		 * @param array $old_instance mixed Array of values for the old form instance.
		 * @param mixed $field mixed Field value.
		 */
		private function get_latest_field_value( $new_instance, $old_instance, $field ) {
			return ! empty( $new_instance[ $field ] )
				? sanitize_text_field( $new_instance[ $field ] )
				: $old_instance[ $field ];
		}

		/**
		 * Gets the product fields from the product post. If no post found
		 * it returns the default values.
		 *
		 * @param int $product_post_id Product Post ID.
		 * @return array $fields Product Fields from the Product Post.
		 */
		private function get_product_from_post( $product_post_id ) {
			$product_post    = get_post( $product_post_id );
			$form_product_id = $product_post_id;
			if ( ! empty( $product_post ) ) {
				$form_product_image_id = get_post_thumbnail_id( $product_post_id );

				return array(
					'form_product_id'          => $form_product_id,
					'form_product_title'       => get_the_title( $product_post ),
					'form_product_description' => $product_post->post_content,
					'form_product_image_id'    => $form_product_image_id,
					'form_product_image_src'   => wp_get_attachment_image_url( $form_product_image_id, 'thumbnail' ),
					'form_product_currency'    => get_post_meta( $product_post_id, 'spay_currency', true ),
					'form_product_price'       => get_post_meta( $product_post_id, 'spay_price', true ),
					'form_product_multiple'    => get_post_meta( $product_post_id, 'spay_multiple', true ) || '0',
					'form_product_email'       => get_post_meta( $product_post_id, 'spay_email', true ),
				);
			}

			return $this->defaults();
		}

		/**
		 * Record a Track event and bump a MC stat.
		 *
		 * @param string $stat_name - the name of the stat.
		 * @param string $event_action - the action we're recording.
		 * @param array  $event_properties - proprties of the event.
		 */
		private function record_event( $stat_name, $event_action, $event_properties = array() ) {
			$current_user = wp_get_current_user();

			// `bumps_stats_extra` only exists on .com
			if ( function_exists( 'bump_stats_extras' ) ) {
				require_lib( 'tracks/client' );
				tracks_record_event( $current_user, 'simple_payments_button_' . $event_action, $event_properties );
				/** This action is documented in modules/widgets/social-media-icons.php */
				do_action( 'jetpack_bump_stats_extra', 'jetpack-simple_payments', $stat_name );
				return;
			}

			$tracking = new Tracking();
			$tracking->tracks_record_event( $current_user, 'jetpack_wpa_simple_payments_button_' . $event_action, $event_properties );
			$jetpack = Jetpack::init();
			// $jetpack->stat automatically prepends the stat group with 'jetpack-'
			$jetpack->stat( 'simple_payments', $stat_name );
			$jetpack->do_stats( 'server_side' );
		}

		/**
		 * Sanitize widget form values as they are saved.
		 *
		 * @see WP_Widget::update()
		 *
		 * @param array $new_instance Values just sent to be saved.
		 * @param array $old_instance Previously saved values from database.
		 *
		 * @return array Updated safe values to be saved.
		 */
		public function update( $new_instance, $old_instance ) {
			$defaults = $this->defaults();
			// do not overrite `product_post_id` for `$new_instance` with the defaults.
			$new_instance = wp_parse_args( $new_instance, array_diff_key( $defaults, array( 'product_post_id' => 0 ) ) );
			$old_instance = wp_parse_args( $old_instance, $defaults );

			$required_widget_props = array(
				'title'           => $this->get_latest_field_value( $new_instance, $old_instance, 'title' ),
				'product_post_id' => $this->get_latest_field_value( $new_instance, $old_instance, 'product_post_id' ),
				'form_action'     => $this->get_latest_field_value( $new_instance, $old_instance, 'form_action' ),
			);

			if ( strcmp( $new_instance['form_action'], $old_instance['form_action'] ) !== 0 ) {
				if ( 'edit' === $new_instance['form_action'] ) {
					return array_merge( $this->get_product_from_post( (int) $old_instance['product_post_id'] ), $required_widget_props );
				}

				if ( 'clear' === $new_instance['form_action'] ) {
					return array_merge( $this->defaults(), $required_widget_props );
				}
			}

			$form_product_image_id = (int) $new_instance['form_product_image_id'];

			$form_product_email = ! empty( $new_instance['form_product_email'] )
				? sanitize_text_field( $new_instance['form_product_email'] )
				: $defaults['form_product_email'];

			return array_merge(
				$required_widget_props,
				array(
					'form_product_id'          => (int) $new_instance['form_product_id'],
					'form_product_title'       => sanitize_text_field( $new_instance['form_product_title'] ),
					'form_product_description' => sanitize_text_field( $new_instance['form_product_description'] ),
					'form_product_image_id'    => $form_product_image_id,
					'form_product_image_src'   => wp_get_attachment_image_url( $form_product_image_id, 'thumbnail' ),
					'form_product_currency'    => sanitize_text_field( $new_instance['form_product_currency'] ),
					'form_product_price'       => sanitize_text_field( $new_instance['form_product_price'] ),
					'form_product_multiple'    => sanitize_text_field( $new_instance['form_product_multiple'] ),
					'form_product_email'       => $form_product_email,
				)
			);
		}

		/**
		 * Back-end widget form.
		 *
		 * @see WP_Widget::form()
		 *
		 * @param array $instance Previously saved values from database.
		 */
		public function form( $instance ) {
			$jetpack_simple_payments = Jetpack_Simple_Payments::get_instance();
			if ( ! method_exists( $jetpack_simple_payments, 'is_enabled_jetpack_simple_payments' ) ) {
				return;
			}
			if ( ! $jetpack_simple_payments->is_enabled_jetpack_simple_payments() ) {
				require __DIR__ . '/simple-payments/admin-warning.php';
				return;
			}

			$instance = wp_parse_args( $instance, $this->defaults() );

			$product_posts = get_posts( // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
				array(
					'numberposts' => 100,
					'orderby'     => 'date',
					'post_type'   => Jetpack_Simple_Payments::$post_type_product,
					'post_status' => 'publish',
				)
			);

			require __DIR__ . '/simple-payments/form.php';
		}
	}

	/**
	 * Register Jetpack_Simple_Payments_Widget widget.
	 */
	function register_widget_jetpack_simple_payments() {
		if ( ! class_exists( 'Jetpack_Simple_Payments' ) ) {
			return;
		}

		$jetpack_simple_payments = Jetpack_Simple_Payments::get_instance();
		if ( ! $jetpack_simple_payments->is_enabled_jetpack_simple_payments() ) {
			return;
		}

		register_widget( 'Jetpack_Simple_Payments_Widget' );
	}
	add_action( 'widgets_init', 'register_widget_jetpack_simple_payments' );
}
