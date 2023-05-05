<?php
/**
 * Jetpack's JITM class.
 *
 * @package automattic/jetpack-jitm
 */

namespace Automattic\Jetpack\JITMS;

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Assets\Logo as Jetpack_Logo;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Status;

/**
 * Jetpack just in time messaging through out the admin
 *
 * @since 1.1.0
 * @since-jetpack 5.6.0
 */
class JITM {

	const PACKAGE_VERSION = '2.3.6';

	/**
	 * The configuration method that is called from the jetpack-config package.
	 */
	public static function configure() {
		$jitm = self::get_instance();
		$jitm->register();
	}

	/**
	 * Pre/Post Connection JITM factory metod
	 *
	 * @return Post_Connection_JITM|Pre_Connection_JITM JITM instance.
	 */
	public static function get_instance() {
		if ( ( new Connection_Manager() )->is_connected() ) {
			$jitm = new Post_Connection_JITM();
		} else {
			$jitm = new Pre_Connection_JITM();
		}
		return $jitm;
	}

	/**
	 * Sets up JITM action callbacks if needed.
	 */
	public function register() {
		if ( did_action( 'jetpack_registered_jitms' ) ) {
			// JITMs have already been registered.
			return;
		}

		if ( ! $this->jitms_enabled() ) {
			// Do nothing.
			return;
		}

		add_action( 'rest_api_init', array( __NAMESPACE__ . '\\Rest_Api_Endpoints', 'register_endpoints' ) );

		add_action( 'current_screen', array( $this, 'prepare_jitms' ) );

		/**
		 * These are sync actions that we need to keep track of for jitms.
		 */
		add_filter( 'jetpack_sync_before_send_updated_option', array( $this, 'jetpack_track_last_sync_callback' ), 99 );

		/**
		 * Fires when the JITMs are registered. This action is used to ensure that
		 * JITMs are registered only once.
		 *
		 * @since 1.16.0
		 */
		do_action( 'jetpack_registered_jitms' );
	}

	/**
	 * Checks the jetpack_just_in_time_msgs filters and whether the site
	 * is offline to determine whether JITMs are enabled.
	 *
	 * @return bool True if JITMs are enabled, else false.
	 */
	public function jitms_enabled() {
		/**
		 * Filter to turn off all just in time messages
		 *
		 * @since 1.1.0
		 * @since-jetpack 3.7.0
		 * @since-jetpack 5.4.0 Correct docblock to reflect default arg value
		 *
		 * @param bool true Whether to show just in time messages.
		 */
		if ( ! apply_filters( 'jetpack_just_in_time_msgs', true ) ) {
			return false;
		}

		// Folks cannot connect to WordPress.com and won't really be able to act on the pre-connection messages. So bail.
		if ( ( new Status() )->is_offline_mode() ) {
			return false;
		}

		return true;
	}

	/**
	 * Prepare actions according to screen and post type.
	 *
	 * @since 1.1.0
	 * @since-jetpack 3.8.2
	 *
	 * @uses Jetpack_Autoupdate::get_possible_failures()
	 *
	 * @param \WP_Screen $screen WP Core's screen object.
	 */
	public function prepare_jitms( $screen ) {
		/**
		 * Filter to hide JITMs on certain screens.
		 *
		 * @since 1.14.0
		 *
		 * @param bool true Whether to show just in time messages.
		 * @param string $string->id The ID of the current screen.
		 */
		if ( apply_filters( 'jetpack_display_jitms_on_screen', true, $screen->id ) ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'jitm_enqueue_files' ) );
			add_action( 'admin_notices', array( $this, 'ajax_message' ) );
			add_action( 'edit_form_top', array( $this, 'ajax_message' ) );
		}
	}

	/**
	 * Function to enqueue jitm css and js
	 */
	public function jitm_enqueue_files() {
		if ( $this->is_gutenberg_page() ) {
			return;
		}

		Assets::register_script(
			'jetpack-jitm',
			'../build/index.js',
			__FILE__,
			array(
				'in_footer'    => true,
				'dependencies' => array( 'jquery' ),
			)
		);
		Assets::enqueue_script( 'jetpack-jitm' );
		wp_localize_script(
			'jetpack-jitm',
			'jitm_config',
			array(
				'api_root'               => esc_url_raw( rest_url() ),
				'activate_module_text'   => esc_html__( 'Activate', 'jetpack-jitm' ),
				'activated_module_text'  => esc_html__( 'Activated', 'jetpack-jitm' ),
				'activating_module_text' => esc_html__( 'Activating', 'jetpack-jitm' ),
				'nonce'                  => wp_create_nonce( 'wp_rest' ),
			)
		);
	}

	/**
	 * Is the current page a block editor page?
	 *
	 * @since 1.1.0
	 * @since-jetpack 8.0.0
	 */
	public function is_gutenberg_page() {
		$current_screen = get_current_screen();
		return ( method_exists( $current_screen, 'is_block_editor' ) && $current_screen->is_block_editor() );
	}

	/**
	 * Get's the current message path for display of a JITM
	 *
	 * @return string The message path
	 */
	public function get_message_path() {
		$screen = get_current_screen();

		return 'wp:' . $screen->id . ':' . current_filter();
	}

	/**
	 * Injects the dom to show a JITM inside of wp-admin.
	 */
	public function ajax_message() {
		if ( ! is_admin() ) {
			return;
		}

		// do not display on Gutenberg pages.
		if ( $this->is_gutenberg_page() ) {
			return;
		}

		$message_path   = $this->get_message_path();
		$query_string   = _http_build_query( $_GET, '', ',' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$current_screen = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Escaped below
		?>
		<div class="jetpack-jitm-message"
			data-nonce="<?php echo esc_attr( wp_create_nonce( 'wp_rest' ) ); ?>"
			data-ajax-nonce="<?php echo esc_attr( wp_create_nonce( 'wp_ajax_action' ) ); ?>"
			data-message-path="<?php echo esc_attr( $message_path ); ?>"
			data-query="<?php echo urlencode_deep( $query_string ); ?>"
			data-redirect="<?php echo urlencode_deep( $current_screen ); ?>"
		></div>
		<?php
	}

	/**
	 * Generate the icon to display on the JITM.
	 *
	 * All icons supported in this method should be included in the array returned by
	 * JITM::get_supported_icons.
	 *
	 * @param string $content_icon Icon type name.
	 * @param bool   $full_jp_logo_exists Is there a big JP logo already displayed on this screen.
	 */
	public function generate_icon( $content_icon, $full_jp_logo_exists ) {
		switch ( $content_icon ) {
			case 'jetpack':
				$jetpack_logo = new Jetpack_Logo();
				$content_icon = '<div class="jp-emblem">' . ( ( $full_jp_logo_exists ) ? $jetpack_logo->get_jp_emblem() : $jetpack_logo->get_jp_emblem_larger() ) . '</div>';
				break;
			case 'woocommerce':
				$content_icon = '<div class="jp-emblem"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" id="Layer_1" x="0px" y="0px" viewBox="0 0 168 100" xml:space="preserve" enable-background="new 0 0 168 100" width="50" height="30"><style type="text/css">
				.st0{clip-path:url(#SVGID_2_);enable-background:new    ;}
				.st1{clip-path:url(#SVGID_4_);}
				.st2{clip-path:url(#SVGID_6_);}
				.st3{clip-path:url(#SVGID_8_);fill:#8F567F;}
				.st4{clip-path:url(#SVGID_10_);fill:#FFFFFE;}
				.st5{clip-path:url(#SVGID_12_);fill:#FFFFFE;}
				.st6{clip-path:url(#SVGID_14_);fill:#FFFFFE;}
			</style><g><defs><polygon id="SVGID_1_" points="83.8 100 0 100 0 0.3 83.8 0.3 167.6 0.3 167.6 100 "/></defs><clipPath id="SVGID_2_"><use xlink:href="#SVGID_1_" overflow="visible"/></clipPath><g class="st0"><g><defs><rect id="SVGID_3_" width="168" height="100"/></defs><clipPath id="SVGID_4_"><use xlink:href="#SVGID_3_" overflow="visible"/></clipPath><g class="st1"><defs><path id="SVGID_5_" d="M15.6 0.3H152c8.6 0 15.6 7 15.6 15.6v52c0 8.6-7 15.6-15.6 15.6h-48.9l6.7 16.4L80.2 83.6H15.6C7 83.6 0 76.6 0 67.9v-52C0 7.3 7 0.3 15.6 0.3"/></defs><clipPath id="SVGID_6_"><use xlink:href="#SVGID_5_" overflow="visible"/></clipPath><g class="st2"><defs><rect id="SVGID_7_" width="168" height="100"/></defs><clipPath id="SVGID_8_"><use xlink:href="#SVGID_7_" overflow="visible"/></clipPath><rect x="-10" y="-9.7" class="st3" width="187.6" height="119.7"/></g></g></g></g></g><g><defs><path id="SVGID_9_" d="M8.4 14.5c1-1.3 2.4-2 4.3-2.1 3.5-0.2 5.5 1.4 6 4.9 2.1 14.3 4.4 26.4 6.9 36.4l15-28.6c1.4-2.6 3.1-3.9 5.2-4.1 3-0.2 4.9 1.7 5.6 5.7 1.7 9.1 3.9 16.9 6.5 23.4 1.8-17.4 4.8-30 9-37.7 1-1.9 2.5-2.9 4.5-3 1.6-0.1 3 0.3 4.3 1.4 1.3 1 2 2.3 2.1 3.9 0.1 1.2-0.1 2.3-0.7 3.3 -2.7 5-4.9 13.2-6.6 24.7 -1.7 11.1-2.3 19.8-1.9 26.1 0.1 1.7-0.1 3.2-0.8 4.5 -0.8 1.5-2 2.4-3.7 2.5 -1.8 0.1-3.6-0.7-5.4-2.5C52.4 66.7 47.4 57 43.7 44.1c-4.4 8.8-7.7 15.3-9.9 19.7 -4 7.7-7.5 11.7-10.3 11.9 -1.9 0.1-3.5-1.4-4.8-4.7 -3.5-9-7.3-26.3-11.3-52C7.1 17.3 7.5 15.8 8.4 14.5"/></defs><clipPath id="SVGID_10_"><use xlink:href="#SVGID_9_" overflow="visible"/></clipPath><rect x="-2.7" y="-0.6" class="st4" width="90.6" height="86.4"/></g><g><defs><path id="SVGID_11_" d="M155.6 25.2c-2.5-4.3-6.1-6.9-11-7.9 -1.3-0.3-2.5-0.4-3.7-0.4 -6.6 0-11.9 3.4-16.1 10.2 -3.6 5.8-5.3 12.3-5.3 19.3 0 5.3 1.1 9.8 3.3 13.6 2.5 4.3 6.1 6.9 11 7.9 1.3 0.3 2.5 0.4 3.7 0.4 6.6 0 12-3.4 16.1-10.2 3.6-5.9 5.3-12.4 5.3-19.4C159 33.4 157.9 28.9 155.6 25.2zM147 44.2c-0.9 4.5-2.7 7.9-5.2 10.1 -2 1.8-3.9 2.5-5.5 2.2 -1.7-0.3-3-1.8-4-4.4 -0.8-2.1-1.2-4.2-1.2-6.2 0-1.7 0.2-3.4 0.5-5 0.6-2.8 1.8-5.5 3.6-8.1 2.3-3.3 4.7-4.8 7.1-4.2 1.7 0.3 3 1.8 4 4.4 0.8 2.1 1.2 4.2 1.2 6.2C147.5 40.9 147.3 42.6 147 44.2z"/></defs><clipPath id="SVGID_12_"><use xlink:href="#SVGID_11_" overflow="visible"/></clipPath><rect x="109.6" y="6.9" class="st5" width="59.4" height="71.4"/></g><g><defs><path id="SVGID_13_" d="M112.7 25.2c-2.5-4.3-6.1-6.9-11-7.9 -1.3-0.3-2.5-0.4-3.7-0.4 -6.6 0-11.9 3.4-16.1 10.2 -3.5 5.8-5.3 12.3-5.3 19.3 0 5.3 1.1 9.8 3.3 13.6 2.5 4.3 6.1 6.9 11 7.9 1.3 0.3 2.5 0.4 3.7 0.4 6.6 0 12-3.4 16.1-10.2 3.5-5.9 5.3-12.4 5.3-19.4C116 33.4 114.9 28.9 112.7 25.2zM104.1 44.2c-0.9 4.5-2.7 7.9-5.2 10.1 -2 1.8-3.9 2.5-5.5 2.2 -1.7-0.3-3-1.8-4-4.4 -0.8-2.1-1.2-4.2-1.2-6.2 0-1.7 0.2-3.4 0.5-5 0.6-2.8 1.8-5.5 3.6-8.1 2.3-3.3 4.7-4.8 7.1-4.2 1.7 0.3 3 1.8 4 4.4 0.8 2.1 1.2 4.2 1.2 6.2C104.6 40.9 104.4 42.6 104.1 44.2z"/></defs><clipPath id="SVGID_14_"><use xlink:href="#SVGID_13_" overflow="visible"/></clipPath><rect x="66.7" y="6.9" class="st6" width="59.4" height="71.4"/></g></svg></div>';
				break;
			default:
				$content_icon = '';
				break;
		}
		return $content_icon;
	}

	/**
	 * Returns an array containing the supported icons for JITMs.
	 *
	 * The list includes an empty string, which is used when no icon should be displayed.
	 *
	 * @return array The list of supported icons.
	 */
	public function get_supported_icons() {
		return array(
			'jetpack',
			'woocommerce',
			'',
		);
	}

	/**
	 * Stores dismiss data into an option
	 *
	 * @param string $key Dismiss key.
	 */
	public function save_dismiss( $key ) {
		$hide_jitm = \Jetpack_Options::get_option( 'hide_jitm' );
		if ( ! is_array( $hide_jitm ) ) {
			$hide_jitm = array();
		}

		if ( ! isset( $hide_jitm[ $key ] ) || ! is_array( $hide_jitm[ $key ] ) ) {
			$hide_jitm[ $key ] = array(
				'last_dismissal' => 0,
				'number'         => 0,
			);
		}

		$hide_jitm[ $key ] = array(
			'last_dismissal' => time(),
			'number'         => $hide_jitm[ $key ]['number'] + 1,
		);

		\Jetpack_Options::update_option( 'hide_jitm', $hide_jitm );
	}

	/**
	 * Sets the 'jetpack_last_plugin_sync' transient when the active_plugins option is synced.
	 *
	 * @param array $params The action parameters.
	 *
	 * @return array Returns the action parameters unchanged.
	 */
	public function jetpack_track_last_sync_callback( $params ) {
		/**
		 * This filter is documented in the Automattic\Jetpack\JITMS\Post_Connection_JITM class.
		 */
		if ( ! apply_filters( 'jetpack_just_in_time_msg_cache', true ) ) {
			return $params;
		}

		if ( is_array( $params ) && isset( $params[0] ) ) {
			$option = $params[0];
			if ( 'active_plugins' === $option ) {
				// Use the cache if we can, but not terribly important if it gets evicted.
				set_transient( 'jetpack_last_plugin_sync', time(), HOUR_IN_SECONDS );
			}
		}

		return $params;
	}
}
