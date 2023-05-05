<?php
/**
 * Instagram Widget. Display some Instagram photos via a widget.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager;

/**
 * This is the actual Instagram widget along with other code that only applies to the widget.
 */
class Jetpack_Instagram_Widget extends WP_Widget {

	const ID_BASE = 'wpcom_instagram_widget'; // Don't change this as Atomic widgets will break.

	/**
	 * Options for the widget.
	 *
	 * @access public
	 *
	 * @var array
	 */
	public $valid_options;

	/**
	 * Default settings for the widgets.
	 *
	 * @access public
	 *
	 * @var array
	 */
	public $defaults;

	/**
	 * Sets the widget properties in WordPress, hooks a few functions, and sets some widget options.
	 */
	public function __construct() {
		parent::__construct(
			self::ID_BASE,
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', esc_html__( 'Instagram', 'jetpack' ) ),
			array(
				'description'           => __( 'Display your latest Instagram photos.', 'jetpack' ),
				'show_instance_in_rest' => true,
			)
		);

		if ( is_active_widget( false, false, self::ID_BASE ) || is_active_widget( false, false, 'monster' ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_css' ) );
		}

		add_action( 'wp_ajax_wpcom_instagram_widget_update_widget_token_id', array( $this, 'ajax_update_widget_token_id' ) );

		$this->valid_options = array(
			/**
			 * Allow changing the maximum number of columns available for the Instagram widget.
			 *
			 * @module widgets
			 *
			 * @since 8.8.0
			 *
			 * @param int $max_columns maximum number of columns.
			 */
			'max_columns' => apply_filters( 'wpcom_instagram_widget_max_columns', 3 ),
			'max_count'   => 20,
		);

		$this->defaults = array(
			'token_id' => null,
			'title'    => __( 'Instagram', 'jetpack' ),
			'columns'  => 2,
			'count'    => 6,
		);

		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the "Instagram" widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = self::ID_BASE;
		return $widget_types;
	}

	/**
	 * Enqueues the widget's frontend CSS but only if the widget is currently in use.
	 */
	public function enqueue_css() {
		wp_enqueue_style( self::ID_BASE, plugins_url( 'instagram/instagram.css', __FILE__ ), array(), JETPACK__VERSION );
	}

	/**
	 * Updates the widget's option in the database to have the passed Keyring token ID.
	 * This is so the user doesn't have to click the "Save" button when we want to set it.
	 *
	 * @param int $token_id A Keyring token ID.
	 * @param int $number The widget ID.
	 */
	public function update_widget_token_id( $token_id, $number = null ) {
		$widget_options = $this->get_settings();

		if ( empty( $number ) ) {
			$number = $this->number;
		}

		if ( ! isset( $widget_options[ $number ] ) || ! is_array( $widget_options[ $number ] ) ) {
			$widget_options[ $number ] = $this->defaults;
		}

		$widget_options[ $number ]['token_id'] = (int) $token_id;

		$this->save_settings( $widget_options );
	}

	/**
	 * Updates the widget's option in the database to have the passed Keyring token ID.
	 *
	 * Sends a json success or error response.
	 */
	public function ajax_update_widget_token_id() {
		if ( ! check_ajax_referer( 'instagram-widget-save-token', 'savetoken', false ) ) {
			wp_send_json_error( array( 'message' => 'bad_nonce' ), 403 );
		}

		if ( ! current_user_can( 'customize' ) ) {
			wp_send_json_error( array( 'message' => 'not_authorized' ), 403 );
		}

		$token_id  = ! empty( $_POST['keyring_id'] ) ? (int) $_POST['keyring_id'] : null;
		$widget_id = ! empty( $_POST['instagram_widget_id'] ) ? (int) $_POST['instagram_widget_id'] : null;

		// For Simple sites check if the token is valid.
		// (For Atomic sites, this check is done via the api: wpcom/v2/instagram/<token_id>).
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$token = Keyring::init()->get_token_store()->get_token(
				array(
					'type' => 'access',
					'id'   => $token_id,
				)
			);
			if ( get_current_user_id() !== (int) $token->meta['user_id'] ) {
				return wp_send_json_error( array( 'message' => 'not_authorized' ), 403 );
			}
		}

		$this->update_widget_token_id( $token_id, $widget_id );
		$this->update_widget_token_legacy_status( false );

		return wp_send_json_success( null, 200 );
	}

	/**
	 * Updates the widget's option in the database to show if it is for legacy API or not.
	 *
	 * @param bool $is_legacy_token A flag to indicate if a token is for the legacy Instagram API.
	 */
	public function update_widget_token_legacy_status( $is_legacy_token ) {
		$widget_options = $this->get_settings();

		if ( ! is_array( $widget_options[ $this->number ] ) ) {
			$widget_options[ $this->number ] = $this->defaults;
		}

		$widget_options[ $this->number ]['is_legacy_token'] = $is_legacy_token;
		$this->save_settings( $widget_options );

		return $is_legacy_token;
	}

	/**
	 * Get's the status of the token from the API
	 *
	 * @param int $token_id A Keyring token ID.
	 * @return array The status of the token's connection.
	 */
	private function get_token_status( $token_id ) {
		if ( empty( $token_id ) ) {
			return array( 'valid' => false );
		}
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$token = Keyring::init()->get_token_store()->get_token(
				array(
					'type' => 'access',
					'id'   => $token_id,
				)
			);

			return array(
				'valid'  => ! empty( $token ),
				'legacy' => $token && 'instagram' === $token->name,
			);
		}

		$site          = Jetpack_Options::get_option( 'id' );
		$path          = sprintf( '/sites/%s/instagram/%s/check-token', $site, $token_id );
		$result        = Client::wpcom_json_api_request_as_blog( $path, 2, array( 'headers' => array( 'content-type' => 'application/json' ) ), null, 'wpcom' );
		$response_code = wp_remote_retrieve_response_code( $result );
		if ( 200 !== $response_code ) {
			return array(
				// We assume the token is valid if the response_code is anything but the invalid
				// token codes we send back. This is to make sure it's not reset, if the API is down
				// or something.
				'valid'  => ! ( 403 === $response_code || 401 === $response_code ),
				'legacy' => 'ERROR',
			);
		}
		$status = json_decode( $result['body'], true );
		return $status;
	}

	/**
	 * Validates the widget instance's token ID and then uses it to fetch images from Instagram.
	 * It then caches the result which it will use on subsequent pageviews.
	 * Keyring is not loaded nor is a remote request is not made in the event of a cache hit.
	 *
	 * @param array $instance A widget $instance, as passed to a widget's widget() method.
	 * @return WP_Error|array A WP_Error on error, an array of images on success.
	 */
	public function get_data( $instance ) {
		if ( empty( $instance['token_id'] ) ) {
			return new WP_Error( 'empty_token', esc_html__( 'The token id was empty', 'jetpack' ), 403 );
		}

		$transient_key = implode( '|', array( 'jetpack_instagram_widget', $instance['token_id'], $instance['count'] ) );
		$cached_images = get_transient( $transient_key );
		if ( $cached_images ) {
			return $cached_images;
		}

		$site   = Jetpack_Options::get_option( 'id' );
		$path   = sprintf( '/sites/%s/instagram/%s?count=%s', $site, $instance['token_id'], $instance['count'] );
		$result = Client::wpcom_json_api_request_as_blog( $path, 2, array( 'headers' => array( 'content-type' => 'application/json' ) ), null, 'wpcom' );

		$response_code = wp_remote_retrieve_response_code( $result );
		if ( 200 !== $response_code ) {
			return new WP_Error( 'invalid_response', esc_html__( 'The response was invalid', 'jetpack' ), $response_code );
		}

		$data = json_decode( wp_remote_retrieve_body( $result ), true );
		if ( ! isset( $data['images'] ) || ! is_array( $data['images'] ) ) {
			return new WP_Error( 'missing_images', esc_html__( 'The images were missing', 'jetpack' ), $response_code );
		}

		set_transient( $transient_key, $data, HOUR_IN_SECONDS );
		return $data;
	}

	/**
	 * Outputs the contents of the widget on the front end.
	 *
	 * If the widget is unconfigured, a configuration message is displayed to users with admin access
	 * and the entire widget is hidden from everyone else to avoid displaying an empty widget.
	 *
	 * @param array $args The sidebar arguments that control the wrapping HTML.
	 * @param array $instance The widget instance (configuration options).
	 */
	public function widget( $args, $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults );
		$data     = $this->get_data( $instance );
		if ( is_wp_error( $data ) ) {
			return;
		}

		$images = $data['images'];

		$status = $this->get_token_status( $instance['token_id'] );
		// Don't display anything to non-blog admins if the widgets is unconfigured or API call fails.
		if ( ( ! $status['valid'] || ! is_array( $images ) ) && ! current_user_can( 'edit_theme_options' ) ) {
			return;
		}

		echo $args['before_widget']; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		// Always show a title on an unconfigured widget.
		if ( ! $status['valid'] && empty( $instance['title'] ) ) {
			$instance['title'] = $this->defaults['title'];
		}

		if ( ! empty( $instance['title'] ) ) {
			echo $args['before_title']; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo $instance['title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo $args['after_title']; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		if ( $status['valid'] && current_user_can( 'edit_theme_options' ) && $status['legacy'] ) {
			echo '<p><em>' . sprintf(
				wp_kses(
					/* translators: %s is a link to reconnect the Instagram widget */
					__( 'In order to continue using this widget you must <a href="%s">reconnect to Instagram</a>.', 'jetpack' ),
					array(
						'a' => array(
							'href' => array(),
						),
					)
				),
				esc_url( add_query_arg( 'instagram_widget_id', $this->number, admin_url( 'widgets.php' ) ) )
			) . '</em></p>';
		}

		if ( ! $status['valid'] ) {
			echo '<p><em>' . sprintf(
				wp_kses(
					/* translators: %s is a link to configure the Instagram widget */
					__( 'In order to use this Instagram widget, you must <a href="%s">configure it</a> first.', 'jetpack' ),
					array(
						'a' => array(
							'href' => array(),
						),
					)
				),
				esc_url( add_query_arg( 'instagram_widget_id', $this->number, admin_url( 'widgets.php' ) ) )
			) . '</em></p>';
		} elseif ( ! is_array( $images ) ) {
			echo '<p>' . esc_html__( 'There was an error retrieving images from Instagram. An attempt will be remade in a few minutes.', 'jetpack' ) . '</p>';
		} elseif ( ! $images ) {
			echo '<p>' . esc_html__( 'No Instagram images were found.', 'jetpack' ) . '</p>';
		} else {
			echo '<div class="' . esc_attr( 'wpcom-instagram-images wpcom-instagram-columns-' . (int) $instance['columns'] ) . '">' . "\n";
			foreach ( $images as $image ) {
				/**
				 * Filter how Instagram image links open in the Instagram widget.
				 *
				 * @module widgets
				 *
				 * @since 8.8.0
				 *
				 * @param string $target Target attribute.
				 */
				$image_target = apply_filters( 'wpcom_instagram_widget_target', '_self' );
				echo '<a href="' . esc_url( $image['link'] ) . '" target="' . esc_attr( $image_target ) . '"><div class="sq-bg-image" style="background-image: url(' . esc_url( set_url_scheme( $image['url'] ) ) . ')"><span class="screen-reader-text">' . esc_attr( $image['title'] ) . '</span></div></a>' . "\n";
			}
			echo "</div>\n";
		}

		echo $args['after_widget']; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is already documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'instagram' );
	}

	/**
	 * Get the URL to connect the widget to Instagram
	 *
	 * @return string the conneciton URL.
	 */
	private function get_connect_url() {
		$connect_url = '';

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM && function_exists( 'wpcom_keyring_get_connect_URL' ) ) {
			$connect_url = wpcom_keyring_get_connect_URL( 'instagram-basic-display', 'instagram-widget' );
		} else {
			$jetpack_blog_id = Jetpack_Options::get_option( 'id' );
			$response        = Client::wpcom_json_api_request_as_user(
				sprintf( '/sites/%d/external-services', $jetpack_blog_id )
			);

			if ( is_wp_error( $response ) ) {
				return $response;
			}

			$body        = json_decode( $response['body'] );
			$connect_url = new WP_Error( 'connect_url_not_found', 'Connect URL not found' );
			if ( ! empty( $body->services->{'instagram-basic-display'}->connect_URL ) ) {
				$connect_url = $body->services->{'instagram-basic-display'}->connect_URL;
			}
		}

		return $connect_url;
	}

	/**
	 * Is this request trying to remove the widgets stored id?
	 *
	 * @param array $status The status of the token's connection.
	 * @return bool if this request trying to remove the widgets stored id.
	 */
	public function removing_widgets_stored_id( $status ) {
		return $status['valid'] && isset( $_GET['instagram_widget_id'] ) && (int) $_GET['instagram_widget_id'] === (int) $this->number && ! empty( $_GET['instagram_widget'] ) && 'remove_token' === $_GET['instagram_widget']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Outputs the widget configuration form for the widget administration page.
	 * Allows the user to add new Instagram Keyring tokens and more.
	 *
	 * @param array $instance The widget instance (configuration options).
	 */
	public function form( $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults );

		if ( ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) && ! ( new Manager() )->is_user_connected() ) {
			echo '<p>';
			printf(
				// translators: %1$1 and %2$s are the opening and closing a tags creating a link to the Jetpack dashboard.
				esc_html__( 'In order to use this widget you need to %1$scomplete your Jetpack connection%2$s by authorizing your user.', 'jetpack' ),
				'<a href="' . esc_url( Jetpack::admin_url( array( 'page' => 'jetpack#/connect-user' ) ) ) . '">',
				'</a>'
			);
			echo '</p>';
			return;
		}

		// If coming back to the widgets page from an action, expand this widget.
		if ( isset( $_GET['instagram_widget_id'] ) && (int) $_GET['instagram_widget_id'] === (int) $this->number ) {
			echo '<script type="text/javascript">jQuery(document).ready(function($){ $(\'.widget[id$="wpcom_instagram_widget-' . esc_js( $this->number ) . '"] .widget-inside\').slideDown(\'fast\'); });</script>';
		}

		$status = $this->get_token_status( $instance['token_id'] );

		// If removing the widget's stored token ID.
		if ( $this->removing_widgets_stored_id( $status ) ) {
			if ( empty( $_GET['nonce'] ) || ! wp_verify_nonce( sanitize_key( $_GET['nonce'] ), 'instagram-widget-remove-token-' . $this->number . '-' . $instance['token_id'] ) ) {
				wp_die( esc_html__( 'Missing or invalid security nonce.', 'jetpack' ) );
			}

			$instance['token_id'] = $this->defaults['token_id'];

			$this->update_widget_token_id( $instance['token_id'] );
			$this->update_widget_token_legacy_status( false );
		} elseif ( $status['valid'] && ( ! isset( $instance['is_legacy_token'] ) || 'ERROR' === $instance['is_legacy_token'] ) ) { // If a token ID is stored, check if we know if it is a legacy API token or not.
			$instance['is_legacy_token'] = $this->update_widget_token_legacy_status( $status['legacy'] );
		} elseif ( ! $status['valid'] ) { // If the token isn't valid reset it.
			$instance['token_id'] = $this->defaults['token_id'];
			$this->update_widget_token_id( $instance['token_id'] );
		}

		// No connection, or a legacy API token? Display a connection link.
		$is_legacy_token = ( isset( $instance['is_legacy_token'] ) && true === $instance['is_legacy_token'] );

		if ( $is_legacy_token ) {
			echo '<p><strong>' . esc_html__( 'In order to continue using this widget you must reconnect to Instagram.', 'jetpack' ) . '</strong></p>';
		}

		if ( is_customize_preview() && ! $instance['token_id'] ) {
			echo '<p>';
			echo wp_kses(
				__( '<strong>Important: You must first click Publish to activate this widget <em>before</em> connecting your account.</strong> After saving the widget, click the button below to connect your Instagram account.', 'jetpack' ),
				array(
					'strong' => array(),
					'em'     => array(),
				)
			);
			echo '</p>';
		}

		if ( ! $instance['token_id'] || $is_legacy_token ) {
			?>
			<script type="text/javascript">
				function getScreenCenterSpecs( width, height ) {
					const screenTop = typeof window.screenTop !== 'undefined' ? window.screenTop : window.screenY,
						screenLeft = typeof window.screenLeft !== 'undefined' ? window.screenLeft : window.screenX;

					return [
						'width=' + width,
						'height=' + height,
						'top=' + ( screenTop + window.innerHeight / 2 - height / 2 ),
						'left=' + ( screenLeft + window.innerWidth / 2 - width / 2 ),
					].join();
				};
				function openWindow( button ) {
					// let's just double check that we aren't getting an unknown random domain injected in here somehow.
					if (! /^https:\/\/public-api.wordpress.com\/connect\//.test(button.dataset.connecturl) ) {
						return;
					}
					window.open(
						button.dataset.connecturl, //TODO: Check if this needs validation it could be a XSS problem. Check the domain maybe?
						'_blank',
						'toolbar=0,location=0,menubar=0,' + getScreenCenterSpecs( 700, 700 )
					);
					button.innerText = '<?php echo esc_js( __( 'Connecting…', 'jetpack' ) ); ?>';
					button.disabled = true;
					window.onmessage = function( { data } ) {
						if ( !! data.keyring_id ) {
							var payload = {
								action: 'wpcom_instagram_widget_update_widget_token_id',
								savetoken: '<?php echo esc_js( wp_create_nonce( 'instagram-widget-save-token' ) ); ?>',
								keyring_id: data.keyring_id,
								instagram_widget_id: button.dataset.widgetid,
							};
							jQuery.post( ajaxurl, payload, function( response ) {
								var widget = jQuery(button).closest('div.widget');
								if ( ! window.wpWidgets ) {
									window.location = '<?php echo esc_js( add_query_arg( array( 'autofocus[panel]' => 'widgets' ), admin_url( 'customize.php' ) ) ); ?>';
								} else {
									wpWidgets.save( widget, 0, 1, 1 );
								}
							} );
						}
					};
				}
			</script>
			<?php
			$connect_url = $this->get_connect_url();
			if ( is_wp_error( $connect_url ) ) {
				echo '<p>' . esc_html__( 'Instagram is currently experiencing connectivity issues, please try again later to connect.', 'jetpack' ) . '</p>';
				return;
			}
			?>
			<p style="text-align:center"><button class="button-primary" onclick="openWindow(this); return false;" data-widgetid="<?php echo esc_attr( $this->number ); ?>" data-connecturl="<?php echo esc_attr( $connect_url ); ?>"><?php echo esc_html( __( 'Connect Instagram Account', 'jetpack' ) ); ?></button></p>

			<?php // Include hidden fields for the widget settings before a connection is made, otherwise the default settings are lost after connecting. ?>
			<input type="hidden" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" value="<?php echo esc_attr( $instance['title'] ); ?>" />
			<input type="hidden" id="<?php echo esc_attr( $this->get_field_id( 'count' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'count' ) ); ?>" value="<?php echo esc_attr( $instance['count'] ); ?>" />
			<input type="hidden" id="<?php echo esc_attr( $this->get_field_id( 'columns' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'columns' ) ); ?>" value="<?php echo esc_attr( $instance['columns'] ); ?>" />

			<?php
			echo '<p><small>' . sprintf(
				wp_kses(
					/* translators: %s is a link to log in to Instagram */
					__( 'Having trouble? Try <a href="%s" target="_blank" rel="noopener noreferrer">logging into the correct account</a> on Instagram.com first.', 'jetpack' ),
					array(
						'a' => array(
							'href'   => array(),
							'target' => array(),
							'rel'    => array(),
						),
					)
				),
				'https://instagram.com/accounts/login/'
			) . '</small></p>';
			return;
		}

		// Connected account.
		$page = ( is_customize_preview() ) ? 'customize.php' : 'widgets.php';

		$query_args = array(
			'instagram_widget_id' => $this->number,
			'instagram_widget'    => 'remove_token',
			'nonce'               => wp_create_nonce( 'instagram-widget-remove-token-' . $this->number . '-' . $instance['token_id'] ),
		);

		if ( is_customize_preview() ) {
			$query_args['autofocus[panel]'] = 'widgets';
		}

		$remove_token_id_url = add_query_arg( $query_args, admin_url( $page ) );

		$data = $this->get_data( $instance );
		// TODO: Revisit the error handling. I think we should be using WP_Error here and
		// Jetpack::Client is the legacy check.
		if ( is_wp_error( $data ) || 'ERROR' === $instance['is_legacy_token'] ) {
			echo '<p>' . esc_html__( 'Instagram is currently experiencing connectivity issues, please try again later to connect.', 'jetpack' ) . '</p>';
			return;
		}
		echo '<p>';
		echo sprintf(
			wp_kses(
				/* translators: %1$s is the URL of the connected Instagram account, %2$s is the username of the connected Instagram account, %3$s is the URL to disconnect the account. */
				__( '<strong>Connected Instagram Account</strong><br /> <a target="_blank" rel="noopener noreferrer" href="%1$s">%2$s</a> | <a href="%3$s">remove</a>', 'jetpack' ),
				array(
					'a'      => array(
						'href'   => array(),
						'rel'    => array(),
						'target' => array(),
					),
					'strong' => array(),
					'br'     => array(),
				)
			),
			esc_url( 'https://instagram.com/' . $data['external_name'] ),
			esc_html( $data['external_name'] ),
			esc_url( $remove_token_id_url )
		);
		echo '</p>';

		// Title.
		echo '<p><label><strong>' . esc_html__( 'Widget Title', 'jetpack' ) . '</strong> <input type="text" id="' . esc_attr( $this->get_field_id( 'title' ) ) . '" name="' . esc_attr( $this->get_field_name( 'title' ) ) . '" value="' . esc_attr( $instance['title'] ) . '" class="widefat" /></label></p>';

		// Number of images to show.
		echo '<p><label>';
		echo '<strong>' . esc_html__( 'Images', 'jetpack' ) . '</strong><br />';
		echo esc_html__( 'Number to display:', 'jetpack' ) . ' ';
		echo '<select name="' . esc_attr( $this->get_field_name( 'count' ) ) . '">';
		for ( $i = 1; $i <= $this->valid_options['max_count']; $i++ ) {
			echo '<option value="' . esc_attr( $i ) . '"' . selected( $i, $instance['count'], false ) . '>' . esc_attr( $i ) . '</option>';
		}
		echo '</select>';
		echo '</label></p>';

		// Columns.
		echo '<p><label>';
		echo '<strong>' . esc_html__( 'Layout', 'jetpack' ) . '</strong><br />';
		echo esc_html__( 'Number of columns:', 'jetpack' ) . ' ';
		echo '<select name="' . esc_attr( $this->get_field_name( 'columns' ) ) . '">';
		for ( $i = 1; $i <= $this->valid_options['max_columns']; $i++ ) {
			echo '<option value="' . esc_attr( $i ) . '"' . selected( $i, $instance['columns'], false ) . '>' . esc_attr( $i ) . '</option>';
		}
		echo '</select>';
		echo '</label></p>';

		echo '<p><small>' . esc_html__( 'New images may take up to 15 minutes to show up on your site.', 'jetpack' ) . '</small></p>';
	}

	/**
	 * Validates and sanitizes the user-supplied widget options.
	 *
	 * @param array $new_instance The user-supplied values.
	 * @param array $old_instance The existing widget options.
	 * @return array A validated and sanitized version of $new_instance.
	 */
	public function update( $new_instance, $old_instance ) {
		$instance = $this->defaults;

		if ( ! empty( $old_instance['token_id'] ) ) {
			$instance['token_id'] = $old_instance['token_id'];
		}

		if ( isset( $new_instance['title'] ) ) {
			$instance['title'] = wp_strip_all_tags( $new_instance['title'] );
		}

		if ( isset( $new_instance['columns'] ) ) {
			$instance['columns'] = max( 1, min( $this->valid_options['max_columns'], (int) $new_instance['columns'] ) );
		}

		if ( isset( $new_instance['count'] ) ) {
			$instance['count'] = max( 1, min( $this->valid_options['max_count'], (int) $new_instance['count'] ) );
		}

		return $instance;
	}
}

add_action(
	'widgets_init',
	function () {
		if ( Jetpack::is_connection_ready() ) {
			register_widget( 'Jetpack_Instagram_Widget' );
		}
	}
);

