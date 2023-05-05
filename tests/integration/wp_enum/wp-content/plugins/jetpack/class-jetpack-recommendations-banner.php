<?php
/**
 * Displays the site type recommendations question as a banner.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Assets\Logo as Jetpack_Logo;
use Automattic\Jetpack\Identity_Crisis;
use Automattic\Jetpack\Tracking;

/**
 * Jetpack_Recommendations_Banner
 **/
class Jetpack_Recommendations_Banner {
	/**
	 * Jetpack_Recommendations_Banner
	 *
	 * @var Jetpack_Recommendations_Banner
	 **/
	private static $instance = null;

	/**
	 * Factory method
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Recommendations_Banner();
		}

		return self::$instance;
	}

	/**
	 * Jetpack_Recommendations_Banner constructor.
	 */
	private function __construct() {
		add_action( 'current_screen', array( $this, 'maybe_initialize_hooks' ) );
	}

	/**
	 * Initialize hooks to display the banner
	 *
	 * @since 9.7 Added the $current_screen parameter.
	 *
	 * @param \WP_Screen $current_screen Current WordPress screen.
	 */
	public function maybe_initialize_hooks( $current_screen ) {
		if ( ! $this->can_be_displayed() ) {
			return;
		}

		if ( Jetpack_Connection_Banner::can_be_displayed( $current_screen ) ) {
			// We don't want to overcrowd the screen with both the Connection banner and the Recommendations banner.
			return;
		}

		add_action( 'admin_print_styles', array( $this, 'admin_banner_styles' ) );
		add_action( 'admin_notices', array( $this, 'render_banner' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_banner_scripts' ) );
	}

	/**
	 * Determines if the banner can be displayed
	 */
	public static function can_be_displayed() {
		if ( ! Jetpack_Recommendations::is_banner_enabled() ) {
			return false;
		}

		// Only the dashboard and plugins pages should see the banner.
		if ( ! in_array( get_current_screen()->id, array( 'dashboard', 'plugins' ), true ) ) {
			return false;
		}

		if ( ! current_user_can( 'jetpack_manage_modules' ) ) {
			return false;
		}

		if ( Jetpack_Options::get_option( 'recommendations_banner_dismissed' ) ) {
			return false;
		}

		if ( ! in_array(
			Jetpack_Options::get_option( 'recommendations_step', 'not-started' ),
			array(
				'not-started',
				'site-type-question',
			),
			true
		) ) {
			return false;
		}

		if ( Identity_Crisis::has_identity_crisis() ) {
			return false;
		}

		return true;
	}

	/**
	 * Handles storing the user responses in the banner.
	 */
	public static function ajax_callback() {
		check_ajax_referer( 'jp-recommendations-banner-nonce', 'nonce' );

		if ( ! current_user_can( 'jetpack_manage_modules' ) ) {
			wp_die();
		}

		$tracking = new Tracking();

		if ( isset( $_REQUEST['dismissBanner'] ) && 'true' === $_REQUEST['dismissBanner'] ) {
			Jetpack_Options::update_option( 'recommendations_banner_dismissed', 1 );
			$tracking->record_user_event( 'recommendations_banner_dismissed' );
			wp_send_json_success();
			wp_die();
		}

		$data = Jetpack_Recommendations::get_recommendations_data();

		$tracking_answers = array();

		if ( isset( $_REQUEST['personal'] ) && is_string( $_REQUEST['personal'] ) ) {
			$value                        = 'true' === $_REQUEST['personal'] ? true : false;
			$data['site-type-personal']   = $value;
			$tracking_answers['personal'] = $value;
		}

		if ( isset( $_REQUEST['builder'] ) && is_string( $_REQUEST['builder'] ) ) {
			$value                       = 'true' === $_REQUEST['builder'] ? true : false;
			$data['site-type-agency']    = $value;
			$tracking_answers['builder'] = $value;
		}

		if ( isset( $_REQUEST['store'] ) && is_string( $_REQUEST['store'] ) ) {
			$value                     = 'true' === $_REQUEST['store'] ? true : false;
			$data['site-type-store']   = $value;
			$tracking_answers['store'] = $value;
		}

		Jetpack_Recommendations::update_recommendations_data( $data );
		Jetpack_Options::update_option( 'recommendations_step', 'banner-completed' );

		$tracking->record_user_event( 'recommendations_banner_answered', $tracking_answers );

		wp_send_json_success();
		wp_die();
	}

	/**
	 * Enqueue JavaScript files.
	 */
	public function enqueue_banner_scripts() {
		wp_enqueue_script(
			'jetpack-recommendations-banner-js',
			Assets::get_file_url_for_environment(
				'_inc/build/jetpack-recommendations-banner.min.js',
				'_inc/jetpack-recommendations-banner.js'
			),
			array( 'jquery' ),
			JETPACK__VERSION,
			true
		);

		wp_localize_script(
			'jetpack-recommendations-banner-js',
			'jp_banner',
			array(
				'nonce'               => wp_create_nonce( 'jp-recommendations-banner-nonce' ),
				'ajax_url'            => admin_url( 'admin-ajax.php' ),
				'recommendations_url' => admin_url( 'admin.php?page=jetpack#/recommendations' ),
			)
		);
	}

	/**
	 * Include the needed styles
	 */
	public function admin_banner_styles() {
		wp_enqueue_style(
			'jetpack-recommendations-banner',
			Assets::get_file_url_for_environment(
				'css/jetpack-recommendations-banner.min.css',
				'css/jetpack-recommendations-banner.css'
			),
			array(),
			JETPACK__VERSION
		);
	}

	/**
	 * Renders the Recommendations Banner
	 */
	public function render_banner() {
		$jetpack_logo = new Jetpack_Logo();
		$site_name    = get_bloginfo( 'name' );
		?>
		<div id="jp-recommendations-banner-main" class="jp-recommendations-banner-main">
			<div class="jp-recommendations-banner__content">
				<div class="jp-recommendations-banner__logo">
					<?php
					echo $jetpack_logo->get_jp_emblem_larger(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>
				</div>
				<h1 class="jp-recommendations-banner__question">
					<?php
					/* translators: placeholder is the name of the website */
					echo sprintf( esc_html__( 'Tell us more about %s?', 'jetpack' ), esc_html( $site_name ) );
					?>
				</h1>
				<p class="jp-recommendations-banner__description">
					<?php esc_html_e( 'To help you get the most from Jetpack, tell us about your site. Check all that apply:', 'jetpack' ); ?>
				</p>
				<div class="jp-recommendations-banner__answer">
					<form id="jp-recommendations-banner__form" class="jp-recommendations-banner__form">
						<div class="jp-recommendations-banner__checkboxes">
							<?php $this->render_checkbox( 'builder', __( 'I build or manage this site for a client', 'jetpack' ) ); ?>
							<?php $this->render_checkbox( 'store', __( 'This is an e-commerce store', 'jetpack' ) ); ?>
							<?php $this->render_checkbox( 'personal', __( 'This is a personal site', 'jetpack' ) ); ?>
						</div>
					</form>
					<a id="jp-recommendations-banner__continue-button" class="jp-banner-cta-button">
						<?php esc_html_e( 'Continue', 'jetpack' ); ?>
					</a>
					<div class="jp-recommendations-banner__continue-description">
						<?php esc_html_e( 'All Jetpack’s great features await you and we’ll recommend some of our favorites', 'jetpack' ); ?>
					</div>
				</div>
			</div>
			<div class="jp-recommendations-banner__illustration-container">
				<button id="jp-recommendations-banner__notice-dismiss" class="jp-recommendations-banner__notice-dismiss">
					<svg class="jp-recommendations-banner__svg-dismiss" width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
						<path fill-rule="evenodd" d="M12.5232 2C7.02034 2 2.57227 6.47 2.57227 12C2.57227 17.53 7.02034 22 12.5232 22C18.0261 22 22.4742 17.53 22.4742 12C22.4742 6.47 18.0261 2 12.5232 2ZM15.1005 8L12.5232 10.59L9.94591 8L8.54283 9.41L11.1201 12L8.54283 14.59L9.94591 16L12.5232 13.41L15.1005 16L16.5036 14.59L13.9263 12L16.5036 9.41L15.1005 8ZM4.56245 12C4.56245 16.41 8.13484 20 12.5232 20C16.9116 20 20.484 16.41 20.484 12C20.484 7.59 16.9116 4 12.5232 4C8.13484 4 4.56245 7.59 4.56245 12Z" />
					</svg>
					<span><?php esc_attr_e( 'Dismiss', 'jetpack' ); ?></span>
				</button>
				<picture>
					<source
						type="image/webp"
						srcset="<?php echo esc_url( $this->img_path( 1, 'webp' ) ); ?> 1x, <?php echo esc_url( $this->img_path( 2, 'webp' ) ); ?> 2x">
					<img
						class="jp-recommendations-banner__illustration-foreground"
						srcset="<?php echo esc_url( $this->img_path( 2 ) ); ?> 2x"
						src="<?php echo esc_url( $this->img_path() ); ?>"
						alt="">
				</picture>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders a checkbox.
	 *
	 * @param string $name The name to give the form input.
	 * @param string $title The title to put on the checkbox.
	 */
	private function render_checkbox( $name, $title ) {
		?>
		<label for="<?php echo esc_html( $name ); ?>" class="jp-recommendations-answer__checkbox-label">
			<input id="<?php echo esc_html( $name ); ?>" name="<?php echo esc_html( $name ); ?>" type="checkbox" tabindex="-1"/>
			<div class="jp-recommendations-answer__title">
				<?php echo esc_html( $title ); ?>
			</div>
		</label>
		<?php
	}

	/**
	 * Returns the path of the banner image for the specified version.
	 *
	 * @param string $res Requested resolution.
	 * @param string $format Requested format.
	 * @return string Path
	 */
	private function img_path( $res = 1, $format = 'png' ) {
		$suffix = 2 === $res ? '-2x' : '';
		$ext    = in_array( $format, array( 'webp', 'png' ), true ) ? $format : 'png';

		return plugins_url( "images/recommendations/assistant-site-type$suffix.$ext", JETPACK__PLUGIN_FILE );
	}
}
