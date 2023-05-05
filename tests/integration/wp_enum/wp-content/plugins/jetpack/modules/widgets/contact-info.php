<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Redirect;

if ( ! class_exists( 'Jetpack_Contact_Info_Widget' ) ) {

	/**
	 * Register Contact_Info_Widget widget
	 */
	function jetpack_contact_info_widget_init() {
		register_widget( 'Jetpack_Contact_Info_Widget' );
	}

	add_action( 'widgets_init', 'jetpack_contact_info_widget_init' );

	/**
	 * Makes a custom Widget for displaying Restaurant Location/Map, Hours, and Contact Info available.
	 *
	 * @package WordPress
	 */
	class Jetpack_Contact_Info_Widget extends WP_Widget {

		/**
		 * Constructor
		 */
		public function __construct() {
			global $pagenow;

			$widget_ops = array(
				'classname'                   => 'widget_contact_info',
				'description'                 => __( 'Display a map with your location, hours, and contact information.', 'jetpack' ),
				'customize_selective_refresh' => true,
				'show_instance_in_rest'       => true,
			);
			parent::__construct(
				'widget_contact_info',
				/** This filter is documented in modules/widgets/facebook-likebox.php */
				apply_filters( 'jetpack_widget_name', __( 'Contact Info & Map', 'jetpack' ) ),
				$widget_ops
			);
			$this->alt_option_name = 'widget_contact_info';

			if ( is_customize_preview() ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
			} elseif ( 'widgets.php' === $pagenow ) {
				add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
			}

			add_action( 'wp_ajax_customize-contact-info-api-key', array( $this, 'ajax_check_api_key' ) );
			add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
		}

		/**
		 * Remove the "Contact info and Map" widget from the Legacy Widget block
		 *
		 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
		 * @return array $widget_types New list of widgets that will be removed.
		 */
		public function hide_widget_in_block_editor( $widget_types ) {
			$widget_types[] = 'widget_contact_info';
			return $widget_types;
		}

		/**
		 * Enqueue scripts and styles.
		 */
		public function enqueue_scripts() {
			wp_enqueue_style(
				'contact-info-map-css',
				plugins_url( 'contact-info/contact-info-map.css', __FILE__ ),
				array(),
				JETPACK__VERSION
			);
		}

		/**
		 * Return an associative array of default values
		 *
		 * These values are used in new widgets.
		 *
		 * @return array Array of default values for the Widget's options
		 */
		public function defaults() {
			return array(
				'title'   => __( 'Hours & Info', 'jetpack' ),
				'address' => __( "3999 Mission Boulevard,\nSan Diego CA 92109", 'jetpack' ),
				'phone'   => _x( '1-202-555-1212', 'Example of a phone number', 'jetpack' ),
				'hours'   => __( "Lunch: 11am - 2pm \nDinner: M-Th 5pm - 11pm, Fri-Sat:5pm - 1am", 'jetpack' ),
				'email'   => null,
				'showmap' => 0,
				'apikey'  => null,
				'goodmap' => null,
			);
		}

		/**
		 * Outputs the HTML for this widget.
		 *
		 * @param array $args     An array of standard parameters for widgets in this theme.
		 * @param array $instance An array of settings for this widget instance.
		 *
		 * @return void Echoes it's output
		 **/
		public function widget( $args, $instance ) {
			$instance = wp_parse_args( $instance, $this->defaults() );

			echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			if ( '' !== $instance['title'] ) {
				echo $args['before_title'] . $instance['title'] . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}

			/**
			 * Fires at the beginning of the Contact Info widget, after the title.
			 *
			 * @module widgets
			 *
			 * @since 3.9.2
			 */
			do_action( 'jetpack_contact_info_widget_start' );

			echo '<div itemscope itemtype="http://schema.org/LocalBusiness">';

			if ( '' !== $instance['address'] ) {

				$showmap = $instance['showmap'];
				$goodmap = isset( $instance['goodmap'] ) ? $instance['goodmap'] : $this->has_good_map( $instance );

				if ( $showmap && true === $goodmap ) {
					/**
					 * Set a Google Maps API Key.
					 *
					 * @since 4.1.0
					 *
					 * @param string $api_key Google Maps API Key
					 */
					$api_key = apply_filters( 'jetpack_google_maps_api_key', $instance['apikey'] );
					echo $this->build_map( $instance['address'], $api_key ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				} elseif ( $showmap && is_customize_preview() && true !== $goodmap ) {
					printf(
						'<span class="contact-map-api-error" style="display: block;">%s</span>',
						esc_html( $instance['goodmap'] )
					);
				}

				$map_link = $this->build_map_link( $instance['address'] );

				printf(
					'<div class="confit-address" itemscope itemtype="http://schema.org/PostalAddress" itemprop="address"><a href="%1$s" target="_blank" rel="noopener noreferrer">%2$s</a></div>',
					esc_url( $map_link ),
					str_replace( "\n", '<br/>', esc_html( $instance['address'] ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
			}

			if ( '' !== $instance['phone'] ) {
				if ( wp_is_mobile() ) {
					echo '<div class="confit-phone"><span itemprop="telephone"><a href="' . esc_url( 'tel:' . $instance['phone'] ) . '">' . esc_html( $instance['phone'] ) . '</a></span></div>';
				} else {
					echo '<div class="confit-phone"><span itemprop="telephone">' . esc_html( $instance['phone'] ) . '</span></div>';
				}
			}

			if ( is_email( trim( $instance['email'] ) ) ) {
				printf(
					'<div class="confit-email"><a href="mailto:%1$s">%1$s</a></div>',
					esc_html( $instance['email'] )
				);
			}

			if ( '' !== $instance['hours'] ) {
				printf(
					'<div class="confit-hours" itemprop="openingHours">%s</div>',
					str_replace( "\n", '<br/>', esc_html( $instance['hours'] ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
			}

			echo '</div>';

			/**
			 * Fires at the end of Contact Info widget.
			 *
			 * @module widgets
			 *
			 * @since 3.9.2
			 */
			do_action( 'jetpack_contact_info_widget_end' );

			echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			/** This action is documented in modules/widgets/gravatar-profile.php */
			do_action( 'jetpack_stats_extra', 'widget_view', 'contact_info' );
		}

		/**
		 * Deals with the settings when they are saved by the admin. Here is
		 * where any validation should be dealt with.
		 *
		 * @param array $new_instance New configuration values.
		 * @param array $old_instance Old configuration values.
		 *
		 * @return array
		 */
		public function update( $new_instance, $old_instance ) {

			$instance            = array();
			$instance['title']   = wp_kses( $new_instance['title'], array() );
			$instance['address'] = wp_kses( $new_instance['address'], array() );
			$instance['phone']   = wp_kses( $new_instance['phone'], array() );
			$instance['email']   = wp_kses( $new_instance['email'], array() );
			$instance['hours']   = wp_kses( $new_instance['hours'], array() );
			$instance['apikey']  = wp_kses( isset( $new_instance['apikey'] ) ? $new_instance['apikey'] : $old_instance['apikey'], array() );

			if ( ! isset( $new_instance['showmap'] ) ) {
				$instance['showmap'] = 0;
			} else {
				$instance['showmap'] = (int) $new_instance['showmap'];
			}

			$instance['goodmap'] = $this->update_goodmap( $old_instance, $instance );

			return $instance;
		}

		/**
		 * Displays the form for this widget on the Widgets page of the WP Admin area.
		 *
		 * @param array $instance Instance configuration.
		 *
		 * @return void
		 */
		public function form( $instance ) {
			$instance = wp_parse_args( $instance, $this->defaults() );
			/** This filter is documented in modules/widgets/contact-info.php */
			$apikey = apply_filters( 'jetpack_google_maps_api_key', $instance['apikey'] );

			wp_enqueue_script(
				'contact-info-admin',
				Assets::get_file_url_for_environment(
					'_inc/build/widgets/contact-info/contact-info-admin.min.js',
					'modules/widgets/contact-info/contact-info-admin.js'
				),
				array( 'jquery' ),
				20160727,
				false
			);

			if ( is_customize_preview() ) {
				$customize_contact_info_api_key_nonce = wp_create_nonce( 'customize_contact_info_api_key' );
				wp_localize_script(
					'contact-info-admin',
					'contact_info_api_key_ajax_obj',
					array( 'nonce' => $customize_contact_info_api_key_nonce )
				);
			}

			?>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title:', 'jetpack' ); ?></label>
				<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['title'] ); ?>" />
			</p>

			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'address' ) ); ?>"><?php esc_html_e( 'Address:', 'jetpack' ); ?></label>
				<textarea class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'address' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'address' ) ); ?>"><?php echo esc_textarea( $instance['address'] ); ?></textarea>
			</p>

			<p>
				<input class="jp-contact-info-showmap" id="<?php echo esc_attr( $this->get_field_id( 'showmap' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'showmap' ) ); ?>" value="1" type="checkbox" <?php checked( $instance['showmap'], 1 ); ?> />
				<label for="<?php echo esc_attr( $this->get_field_id( 'showmap' ) ); ?>"><?php esc_html_e( 'Show map', 'jetpack' ); ?></label>
			</p>

			<?php if ( ! has_filter( 'jetpack_google_maps_api_key' ) || false === apply_filters( 'jetpack_google_maps_api_key', false ) ) { ?>

			<p class="jp-contact-info-admin-map" style="<?php echo $instance['showmap'] ? '' : 'display: none;'; ?>">
				<label for="<?php echo esc_attr( $this->get_field_id( 'apikey' ) ); ?>">
					<?php esc_html_e( 'Google Maps API Key', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'apikey' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'apikey' ) ); ?>" type="text" value="<?php echo esc_attr( $apikey ); ?>" />
					<br />
					<small>
					<?php
					printf(
						wp_kses(
							/* Translators: placeholder is a URL to support documentation. */
							__( 'Google now requires an API key to use their maps on your site. <a href="%s">See our documentation</a> for instructions on acquiring a key.', 'jetpack' ),
							array(
								'a' => array(
									'href' => true,
								),
							)
						),
						( defined( 'IS_WPCOM' ) && IS_WPCOM ) ? 'https://wordpress.com/support/widgets/contact-info/' : esc_url( Redirect::get_url( 'jetpack-support-extra-sidebar-widgets-contact-info-widget' ) )
					);
					?>
					</small>
				</label>
			</p>

			<?php } else { ?>

			<input type="hidden" id="<?php echo esc_attr( $this->get_field_id( 'apikey' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'apikey' ) ); ?>" value="<?php echo esc_attr( $apikey ); ?>" />

			<?php } // end if jetpack_google_maps_api_key check. ?>

			<p class="jp-contact-info-admin-map jp-contact-info-embed-map" style="<?php echo $instance['showmap'] ? '' : 'display: none;'; ?>">
				<?php
				if ( ! is_customize_preview() && true === $instance['goodmap'] ) {
					echo $this->build_map( $instance['address'], $apikey ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				} elseif ( true !== $instance['goodmap'] && ! empty( $instance['goodmap'] ) ) {
					printf(
						'<span class="button-link-delete">%s</span>',
						esc_html( $instance['goodmap'] )
					);
				}
				?>
			</p>

			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'phone' ) ); ?>"><?php esc_html_e( 'Phone:', 'jetpack' ); ?></label>
				<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'phone' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'phone' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['phone'] ); ?>" />
			</p>

			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'email' ) ); ?>"><?php esc_html_e( 'Email Address:', 'jetpack' ); ?></label>
				<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'email' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'email' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['email'] ); ?>" />
			</p>

			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'hours' ) ); ?>"><?php esc_html_e( 'Hours:', 'jetpack' ); ?></label>
				<textarea class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'hours' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'hours' ) ); ?>"><?php echo esc_textarea( $instance['hours'] ); ?></textarea>
			</p>

			<?php
		}

		/**
		 * Generate a Google Maps link for the supplied address.
		 *
		 * @param string $address Address to link to.
		 *
		 * @return string
		 */
		private function build_map_link( $address ) {
			// Google map urls have lots of available params but zoom (z) and query (q) are enough.
			return 'https://maps.google.com/maps?z=16&q=' . $this->urlencode_address( $address );
		}

		/**
		 * Builds map display HTML code from the supplied address.
		 *
		 * @param string $address Address.
		 * @param string $api_key API Key.
		 *
		 * @return string HTML of the map.
		 */
		private function build_map( $address, $api_key = null ) {
			$this->enqueue_scripts();
			$src = add_query_arg( 'q', rawurlencode( $address ), 'https://www.google.com/maps/embed/v1/place' );
			if ( ! empty( $api_key ) ) {
				$src = add_query_arg( 'key', $api_key, $src );
			}

			$height = 216;

			$iframe_attributes = sprintf(
				' height="%d" frameborder="0" src="%s" title="%s" class="contact-map"',
				esc_attr( $height ),
				esc_url( $src ),
				__( 'Google Map Embed', 'jetpack' )
			);

			$iframe_html = sprintf( '<iframe width="600" %s></iframe>', $iframe_attributes );

			if (
				! class_exists( 'Jetpack_AMP_Support' )
				|| ! Jetpack_AMP_Support::is_amp_request()
			) {
				return $iframe_html;
			}

			$amp_iframe_html = sprintf( '<amp-iframe layout="fixed-height" width="auto" sandbox="allow-scripts allow-same-origin" %s>', $iframe_attributes );

			// Add placeholder to avoid AMP error: <amp-iframe> elements must be positioned outside the first 75% of the viewport or 600px from the top (whichever is smaller).
			$amp_iframe_html .= sprintf( '<span placeholder>%s</span>', esc_html__( 'Loading map&hellip;', 'jetpack' ) );

			// Add original iframe as fallback in case JavaScript is disabled.
			$amp_iframe_html .= sprintf( '<noscript>%s</noscript>', $iframe_html );

			$amp_iframe_html .= '</amp-iframe>';
			return $amp_iframe_html;
		}

		/**
		 * Encode an URL
		 *
		 * @param string $address The URL to encode.
		 *
		 * @return string The encoded URL
		 */
		private function urlencode_address( $address ) {

			$address = strtolower( $address );
			// Get rid of any unwanted whitespace.
			$address = preg_replace( '/\s+/', ' ', trim( $address ) );
			// Use + not %20.
			$address = str_ireplace( ' ', '+', $address );
			return rawurlencode( $address );
		}

		/**
		 * Returns the instance's updated 'goodmap' value.
		 *
		 * @param array $old_instance Old configuration values.
		 * @param array $instance Current configuration values.
		 *
		 * @return bool|string The instance's updated 'goodmap' value. The value is true if
		 * $instance can display a good map. If not, returns an error message.
		 */
		private function update_goodmap( $old_instance, $instance ) {
			/*
			 * If we have no address or don't want to show a map,
			 * no need to check if the map is valid.
			 */
			if ( empty( $instance['address'] ) || 0 === $instance['showmap'] ) {
				return false;
			}

			/*
			 * If there have been any changes that may impact the map in the widget
			 * (adding an address, address changes, new API key, API key change)
			 * then we want to check whether our map can be displayed again.
			 */
			if (
				! isset( $instance['goodmap'] )
				|| ! isset( $old_instance['address'] )
				|| $this->urlencode_address( $old_instance['address'] ) !== $this->urlencode_address( $instance['address'] )
				|| ! isset( $old_instance['apikey'] )
				|| $old_instance['apikey'] !== $instance['apikey']
			) {
				return $this->has_good_map( $instance );
			} else {
				return $instance['goodmap'];
			}
		}

		/**
		 * Check if the instance has a valid Map location.
		 *
		 * @param array $instance Widget instance configuration.
		 *
		 * @return bool|string Whether or not there is a valid map. If not, return an error message.
		 */
		private function has_good_map( $instance ) {
			/** This filter is documented in modules/widgets/contact-info.php */
			$api_key = apply_filters( 'jetpack_google_maps_api_key', $instance['apikey'] );
			if ( ! empty( $api_key ) ) {
				$path               = add_query_arg(
					array(
						'q'   => rawurlencode( $instance['address'] ),
						'key' => $api_key,
					),
					'https://www.google.com/maps/embed/v1/place'
				);
				$wp_remote_get_args = array(
					'headers' => array( 'Referer' => home_url() ),
				);
				$response           = wp_remote_get( esc_url_raw( $path ), $wp_remote_get_args );

				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					return true;
				} else {
					return wp_remote_retrieve_body( $response );
				}
			}

			return __( 'Please enter a valid Google API Key.', 'jetpack' );
		}

		/**
		 * Check the Google Maps API key after an Ajax call from the widget's admin form in
		 * the Customizer preview.
		 */
		public function ajax_check_api_key() {
			if ( isset( $_POST['apikey'] ) ) {
				if ( check_ajax_referer( 'customize_contact_info_api_key' ) && current_user_can( 'customize' ) ) {
					$apikey                     = wp_kses( wp_unslash( $_POST['apikey'] ), array() );
					$default_instance           = $this->defaults();
					$default_instance['apikey'] = $apikey;
					wp_send_json( array( 'result' => esc_html( $this->has_good_map( $default_instance ) ) ) );
				}
			} else {
				wp_die();
			}
		}

	}

}
