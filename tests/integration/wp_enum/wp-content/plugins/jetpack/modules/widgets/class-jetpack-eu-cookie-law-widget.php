<?php
/**
 * Main class file for EU Cookie Law Widget.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Jetpack_EU_Cookie_Law_Widget' ) ) {
	/**
	 * EU Cookie Law Widget
	 *
	 * Display the EU Cookie Law banner in the bottom part of the screen.
	 */
	class Jetpack_EU_Cookie_Law_Widget extends WP_Widget {
		/**
		 * EU Cookie Law cookie name.
		 *
		 * @var string
		 */
		public static $cookie_name = 'eucookielaw';

		/**
		 * Default hide options.
		 *
		 * @var array
		 */
		private $hide_options = array(
			'button',
			'scroll',
			'time',
		);

		/**
		 * Default text options.
		 *
		 * @var array
		 */
		private $text_options = array(
			'default',
			'custom',
		);

		/**
		 * Default color scheme options.
		 *
		 * @var array
		 */
		private $color_scheme_options = array(
			'default',
			'negative',
		);

		/**
		 * Default policy URL options.
		 *
		 * @var array
		 */
		private $policy_url_options = array(
			'default',
			'custom',
		);

		/**
		 * Widget position options.
		 *
		 * @var array
		 */
		private $position_options = array(
			'bottom',
			'top',
		);

		/**
		 * Constructor.
		 */
		public function __construct() {
			parent::__construct(
				'eu_cookie_law_widget',
				/** This filter is documented in modules/widgets/facebook-likebox.php */
				apply_filters( 'jetpack_widget_name', esc_html__( 'Cookies & Consents Banner', 'jetpack' ) ),
				array(
					'description'                 => esc_html__( 'Display a banner for EU Cookie Law and GDPR compliance.', 'jetpack' ),
					'customize_selective_refresh' => true,
				),
				array()
			);

			if ( is_active_widget( false, false, $this->id_base ) || is_customize_preview() ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_frontend_scripts' ) );
			}
		}

		/**
		 * Enqueue scripts and styles.
		 */
		public function enqueue_frontend_scripts() {
			wp_enqueue_style( 'eu-cookie-law-style', plugins_url( 'eu-cookie-law/style.css', __FILE__ ), array(), JETPACK__VERSION );

			if ( ! class_exists( 'Jetpack_AMP_Support' ) || ! Jetpack_AMP_Support::is_amp_request() ) {
				wp_enqueue_script(
					'eu-cookie-law-script',
					Assets::get_file_url_for_environment(
						'_inc/build/widgets/eu-cookie-law/eu-cookie-law.min.js',
						'modules/widgets/eu-cookie-law/eu-cookie-law.js'
					),
					array(),
					'20180522',
					true
				);
			}
		}

		/**
		 * Return an associative array of default values.
		 *
		 * These values are used in new widgets.
		 *
		 * @return array Default values for the widget options.
		 */
		public function defaults() {
			return array(
				'hide'               => $this->hide_options[0],
				'hide-timeout'       => 30,
				'consent-expiration' => 180,
				'text'               => $this->text_options[0],
				'customtext'         => '',
				'color-scheme'       => $this->color_scheme_options[0],
				'policy-url'         => get_option( 'wp_page_for_privacy_policy' ) ? $this->policy_url_options[1] : $this->policy_url_options[0],
				'default-policy-url' => 'https://automattic.com/cookies/',
				'custom-policy-url'  => get_option( 'wp_page_for_privacy_policy' ) ? get_permalink( (int) get_option( 'wp_page_for_privacy_policy' ) ) : '',
				'position'           => $this->position_options[0],
				'policy-link-text'   => esc_html__( 'Cookie Policy', 'jetpack' ),
				'button'             => esc_html__( 'Close and accept', 'jetpack' ),
				'default-text'       => esc_html__( "Privacy & Cookies: This site uses cookies. By continuing to use this website, you agree to their use. \r\nTo find out more, including how to control cookies, see here:", 'jetpack' ),
			);
		}

		/**
		 * Front-end display of the widget.
		 *
		 * @param array $args     Widget arguments.
		 * @param array $instance Saved values from database.
		 */
		public function widget( $args, $instance ) {
			/**
			 * Filters the display of the EU Cookie Law widget.
			 *
			 * @since 6.1.1
			 *
			 * @param bool true Should the EU Cookie Law widget be disabled. Default to false.
			 */
			if ( apply_filters( 'jetpack_disable_eu_cookie_law_widget', false ) ) {
				return;
			}

			$instance = wp_parse_args( $instance, $this->defaults() );

			if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
				require __DIR__ . '/eu-cookie-law/widget-amp.php';
				return;
			}

			$classes         = array();
			$classes['hide'] = 'hide-on-' . esc_attr( $instance['hide'] );
			if ( 'negative' === $instance['color-scheme'] ) {
				$classes['negative'] = 'negative';
			}

			if ( 'top' === $instance['position'] ) {
				$classes['top'] = 'top';
			}

			if ( Jetpack::is_module_active( 'wordads' ) ) {
				$classes['ads']  = 'ads-active';
				$classes['hide'] = 'hide-on-button';
			}

			/**
			 * Check if widget is loaded in widgets.php.
			 *
			 * @return string widget Static version of the widget for better preview.
			 */
			global $pagenow;
			if ( 'widgets.php' === $pagenow ) {
				// To prevent the widget from being added as a pop-up
				// we do not echo the before and after $args. Instead we wrap
				// it in a dummy `div` and return before the `widget_view` is
				// added to stats.
				echo '<div id="eu-cookie-law" style="padding: 0;margin: 5px">';
				require_once __DIR__ . '/eu-cookie-law/widget.php';
				echo '</div>';
				return;
			}

			echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			require_once __DIR__ . '/eu-cookie-law/widget.php';
			echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			/** This action is already documented in modules/widgets/gravatar-profile.php */
			do_action( 'jetpack_stats_extra', 'widget_view', 'eu_cookie_law' );
		}

		/**
		 * Back-end widget form.
		 *
		 * @param array $instance Previously saved values from database.
		 */
		public function form( $instance ) {
			$instance = wp_parse_args( $instance, $this->defaults() );
			if ( Jetpack::is_module_active( 'wordads' ) ) {
				$instance['hide'] = 'button';
			}

			wp_enqueue_script(
				'eu-cookie-law-widget-admin',
				Assets::get_file_url_for_environment(
					'_inc/build/widgets/eu-cookie-law/eu-cookie-law-admin.min.js',
					'modules/widgets/eu-cookie-law/eu-cookie-law-admin.js'
				),
				array( 'jquery' ),
				20180417,
				false
			);

			require __DIR__ . '/eu-cookie-law/form.php';
		}

		/**
		 * Sanitize widget form values as they are saved.
		 *
		 * @param array $new_instance Values just sent to be saved.
		 * @param array $old_instance Previously saved values from database.
		 * @return array Updated safe values to be saved.
		 */
		public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			$instance = array();
			$defaults = $this->defaults();

			$instance['hide']         = $this->filter_value( isset( $new_instance['hide'] ) ? $new_instance['hide'] : '', $this->hide_options );
			$instance['text']         = $this->filter_value( isset( $new_instance['text'] ) ? $new_instance['text'] : '', $this->text_options );
			$instance['color-scheme'] = $this->filter_value( isset( $new_instance['color-scheme'] ) ? $new_instance['color-scheme'] : '', $this->color_scheme_options );
			$instance['policy-url']   = $this->filter_value( isset( $new_instance['policy-url'] ) ? $new_instance['policy-url'] : '', $this->policy_url_options );
			$instance['position']     = $this->filter_value( isset( $new_instance['position'] ) ? $new_instance['position'] : '', $this->position_options );

			if ( isset( $new_instance['hide-timeout'] ) ) {
				// Time can be a value between 3 and 1000 seconds.
				$instance['hide-timeout'] = min( 1000, max( 3, (int) $new_instance['hide-timeout'] ) );
			}

			if ( isset( $new_instance['consent-expiration'] ) ) {
				// Time can be a value between 1 and 365 days.
				$instance['consent-expiration'] = min( 365, max( 1, (int) $new_instance['consent-expiration'] ) );
			}

			if ( isset( $new_instance['customtext'] ) ) {
				$instance['customtext'] = mb_substr( wp_kses( $new_instance['customtext'], array() ), 0, 4096 );
			} else {
				$instance['text'] = $this->text_options[0];
			}

			if ( isset( $new_instance['policy-url'] ) ) {
				$instance['policy-url'] = 'custom' === $new_instance['policy-url']
					? 'custom'
					: 'default';
			} else {
				$instance['policy-url'] = $this->policy_url_options[0];
			}

			if ( 'custom' === $instance['policy-url'] && isset( $new_instance['custom-policy-url'] ) ) {
				$instance['custom-policy-url'] = esc_url( $new_instance['custom-policy-url'], array( 'http', 'https' ) );

				if ( strlen( $instance['custom-policy-url'] ) < 10 ) {
					unset( $instance['custom-policy-url'] );
					global $wp_customize;
					if ( ! isset( $wp_customize ) ) {
						$instance['policy-url'] = $this->policy_url_options[0];
					}
				}
			}

			if ( isset( $new_instance['policy-link-text'] ) ) {
				$instance['policy-link-text'] = trim( mb_substr( wp_kses( $new_instance['policy-link-text'], array() ), 0, 100 ) );
			}

			if ( empty( $instance['policy-link-text'] ) || $instance['policy-link-text'] === $defaults['policy-link-text'] ) {
				unset( $instance['policy-link-text'] );
			}

			if ( isset( $new_instance['button'] ) ) {
				$instance['button'] = trim( mb_substr( wp_kses( $new_instance['button'], array() ), 0, 100 ) );
			}

			if ( empty( $instance['button'] ) || $instance['button'] === $defaults['button'] ) {
				unset( $instance['button'] );
			}

			// Show the banner again if a setting has been changed.
			setcookie( self::$cookie_name, '', time() - 86400, '/', COOKIE_DOMAIN, is_ssl(), false ); // phpcs:ignore Jetpack.Functions.SetCookie -- Fine to have accessible.

			return $instance;
		}

		/**
		 * Check if the value is allowed and not empty.
		 *
		 * @param  string $value Value to check.
		 * @param  array  $allowed Array of allowed values.
		 *
		 * @return string $value if pass the check or first value from allowed values.
		 */
		public function filter_value( $value, $allowed = array() ) {
			$allowed = (array) $allowed;
			if ( empty( $value ) || ( ! empty( $allowed ) && ! in_array( $value, $allowed, true ) ) ) {
				$value = $allowed[0];
			}
			return $value;
		}
	}

	// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move these functions to some other file.

	/**
	 * Register Jetpack_EU_Cookie_Law_Widget widget.
	 */
	function jetpack_register_eu_cookie_law_widget() {
		register_widget( 'Jetpack_EU_Cookie_Law_Widget' );
	}

	add_action( 'widgets_init', 'jetpack_register_eu_cookie_law_widget' );
}
