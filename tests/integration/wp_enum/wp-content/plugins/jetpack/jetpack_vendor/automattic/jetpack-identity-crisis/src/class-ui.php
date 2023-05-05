<?php
/**
 * Identity_Crisis package.
 *
 * @package  automattic/jetpack-identity-crisis
 */

namespace Automattic\Jetpack\IdentityCrisis;

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Identity_Crisis;
use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Tracking as Tracking;
use Jetpack_Options;
use Jetpack_Tracks_Client;

/**
 * The Identity Crisis UI handling.
 */
class UI {

	/**
	 * Temporary storage for consumer data.
	 *
	 * @var array
	 */
	private static $consumers;

	/**
	 * Initialization.
	 */
	public static function init() {
		if ( did_action( 'jetpack_identity_crisis_ui_init' ) ) {
			return;
		}

		/**
		 * Action called after initializing Identity Crisis UI.
		 *
		 * @since 0.6.0
		 */
		do_action( 'jetpack_identity_crisis_ui_init' );

		$idc_data = Identity_Crisis::check_identity_crisis();

		if ( false === $idc_data ) {
			return;
		}

		add_action( 'admin_enqueue_scripts', array( static::class, 'enqueue_scripts' ) );

		Tracking::register_tracks_functions_scripts( true );
	}

	/**
	 * Enqueue scripts!
	 */
	public static function enqueue_scripts() {
		if ( is_admin() ) {
			Assets::register_script(
				'jp_identity_crisis_banner',
				'../build/index.js',
				__FILE__,
				array(
					'in_footer'  => true,
					'textdomain' => 'jetpack-idc',
				)
			);
			Assets::enqueue_script( 'jp_identity_crisis_banner' );
			wp_add_inline_script( 'jp_identity_crisis_banner', static::get_initial_state(), 'before' );

			add_action( 'admin_notices', array( static::class, 'render_container' ) );
		}
	}

	/**
	 * Create the container element for the IDC banner.
	 */
	public static function render_container() {
		?>
		<div id="jp-identity-crisis-container" class="notice"></div>
		<?php
	}

	/**
	 * Return the rendered initial state JavaScript code.
	 *
	 * @return string
	 */
	private static function get_initial_state() {
		return 'var JP_IDENTITY_CRISIS__INITIAL_STATE=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( static::get_initial_state_data() ) ) . '"));';
	}

	/**
	 * Get the initial state data.
	 *
	 * @return array
	 */
	private static function get_initial_state_data() {
		$idc_urls                           = Identity_Crisis::get_mismatched_urls();
		$current_screen                     = get_current_screen();
		$is_admin                           = current_user_can( 'jetpack_disconnect' );
		$possible_dynamic_site_url_detected = (bool) Identity_Crisis::detect_possible_dynamic_site_url();

		return array(
			'WP_API_root'                    => esc_url_raw( rest_url() ),
			'WP_API_nonce'                   => wp_create_nonce( 'wp_rest' ),
			'wpcomHomeUrl'                   => ( is_array( $idc_urls ) && array_key_exists( 'wpcom_url', $idc_urls ) ) ? $idc_urls['wpcom_url'] : null,
			'currentUrl'                     => ( is_array( $idc_urls ) && array_key_exists( 'current_url', $idc_urls ) ) ? $idc_urls['current_url'] : null,
			'redirectUri'                    => isset( $_SERVER['REQUEST_URI'] ) ? str_replace( '/wp-admin/', '/', filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ) ) : '',
			'tracksUserData'                 => Jetpack_Tracks_Client::get_connected_user_tracks_identity(),
			'tracksEventData'                => array(
				'isAdmin'       => $is_admin,
				'currentScreen' => $current_screen ? $current_screen->id : false,
				'blogID'        => Jetpack_Options::get_option( 'id' ),
				'platform'      => static::get_platform(),
			),
			'isSafeModeConfirmed'            => Identity_Crisis::$is_safe_mode_confirmed,
			'consumerData'                   => static::get_consumer_data(),
			'isAdmin'                        => $is_admin,
			'possibleDynamicSiteUrlDetected' => $possible_dynamic_site_url_detected,
		);
	}

	/**
	 * Get the package consumer data.
	 *
	 * @return array
	 */
	public static function get_consumer_data() {
		if ( null !== static::$consumers ) {
			return static::$consumers;
		}

		$consumers = apply_filters( 'jetpack_idc_consumers', array() );

		if ( ! $consumers ) {
			return array();
		}

		usort(
			$consumers,
			function ( $c1, $c2 ) {
				$priority1 = ( array_key_exists( 'priority', $c1 ) && (int) $c1['priority'] ) ? (int) $c1['priority'] : 10;
				$priority2 = ( array_key_exists( 'priority', $c2 ) && (int) $c2['priority'] ) ? (int) $c2['priority'] : 10;

				return $priority1 > $priority2 ? 1 : -1;
			}
		);

		$consumer_chosen     = null;
		$consumer_url_length = 0;

		foreach ( $consumers as $consumer ) {
			if ( empty( $consumer['admin_page'] ) || ! is_string( $consumer['admin_page'] ) ) {
				continue;
			}

			if ( isset( $_SERVER['REQUEST_URI'] ) && 0 === strpos( filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ), $consumer['admin_page'] ) && strlen( $consumer['admin_page'] ) > $consumer_url_length ) {
				$consumer_chosen     = $consumer;
				$consumer_url_length = strlen( $consumer['admin_page'] );
			}
		}

		static::$consumers = $consumer_chosen ? $consumer_chosen : array_shift( $consumers );

		return static::$consumers;
	}

	/**
	 * Get the site platform.
	 *
	 * @return string
	 */
	private static function get_platform() {
		$host = new Host();

		if ( $host->is_woa_site() ) {
			return 'woa';
		}

		if ( $host->is_vip_site() ) {
			return 'vip';
		}

		if ( $host->is_newspack_site() ) {
			return 'newspack';
		}

		return 'self-hosted';
	}

}
