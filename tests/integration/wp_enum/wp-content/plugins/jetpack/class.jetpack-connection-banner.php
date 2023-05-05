<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack connection banner.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Assets\Logo;
use Automattic\Jetpack\Licensing;

/**
 * Jetpack connection banner.
 */
class Jetpack_Connection_Banner {
	/**
	 * Static instance.
	 *
	 * @var Jetpack_Connection_Banner
	 */
	private static $instance = null;

	/**
	 * Initialize and fetch the static instance.
	 *
	 * @return self
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Connection_Banner();
		}

		return self::$instance;
	}

	/**
	 * Jetpack_Connection_Banner constructor.
	 *
	 * Since we call the Jetpack_Connection_Banner:init() method from the `Jetpack` class, and after
	 * the admin_init action fires, we know that the admin is initialized at this point.
	 */
	private function __construct() {
		add_action( 'current_screen', array( $this, 'maybe_initialize_hooks' ) );
	}

	/**
	 * The banner is forcibly displayed.
	 *
	 * @return bool
	 */
	public static function force_display() {
		/**
		 * This is an experiment for partners to test. Allow customization of the behavior of pre-connection banners.
		 *
		 * @since 8.6.0
		 *
		 * @param bool $always_show_prompt Should this prompt always appear? Default to false.
		 */
		return apply_filters( 'jetpack_pre_connection_prompt_helpers', false );
	}

	/**
	 * Can the banner be displayed for the given screen?
	 *
	 * @param \WP_Screen $current_screen Current WordPress screen.
	 *
	 * @return bool
	 */
	public static function can_be_displayed( $current_screen ) {
		$has_connected_owner = Jetpack::connection()->has_connected_owner();
		$is_connected        = Jetpack::is_connection_ready();
		$has_licenses        = ! empty( Licensing::instance()->stored_licenses() );

		// Don't show the connect notice if the site has a connected owner.
		if ( $has_connected_owner ) {
			return false;
		}

		// Don't show the connect notice if a site connection is established and there are no stored licenses.
		// Stored licenses indicate that a purchased product may not be provisioned yet hence we need to keep
		// showing the notice to nudge the user to connect in order to have their product(s) provisioned.
		if ( $is_connected && ! $has_licenses ) {
			return false;
		}

		// Kill if banner has been dismissed and the pre-connection helpers filter is not set.
		if (
			Jetpack_Options::get_option( 'dismissed_connection_banner' ) &&
			! self::force_display()
		) {
			return false;
		}

		// Don't show the connect notice anywhere but the plugins.php after activating.
		if ( 'plugins' !== $current_screen->base && 'dashboard' !== $current_screen->base ) {
			return false;
		}

		if ( ! current_user_can( 'jetpack_connect' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Given a string for the the banner was added, and an int that represents the slide to
	 * a URL for, this function returns a connection URL with a from parameter that will
	 * support split testing.
	 *
	 * @since 7.2   Event key format is now banner-connect-banner-72-dashboard or connect-banner-72-plugins.
	 *              The param $slide_num was removed since we removed all slides but the first one.
	 * @since 4.4.0
	 *
	 * @param string $jp_version_banner_added A short version of when the banner was added. Ex. 44.
	 * @return string
	 */
	public function build_connect_url_for_slide( $jp_version_banner_added ) {
		global $current_screen;
		$url = Jetpack::init()->build_connect_url(
			true,
			false,
			sprintf( 'connect-banner-%s-%s', $jp_version_banner_added, $current_screen->base )
		);
		return add_query_arg( 'auth_approved', 'true', $url );
	}

	/**
	 * Will initialize hooks to display the new (as of 4.4) connection banner if the current user can
	 * connect Jetpack, if Jetpack has not been deactivated, and if the current page is the plugins or dashboard page.
	 *
	 * @since 4.4.0
	 * @since 4.5.0 Made the new (as of 4.4) connection banner display to everyone by default.
	 * @since 5.3.0 Running another split test between 4.4 banner and a new one in 5.3.
	 * @since 7.2   B test was removed.
	 * @since 9.7   Moved the connection condition checking to this method to fulfill Licensing requirements.
	 *
	 * @param \WP_Screen $current_screen Current WordPress screen.
	 */
	public function maybe_initialize_hooks( $current_screen ) {
		if ( ! self::can_be_displayed( $current_screen ) ) {
			return;
		}

		if ( ! empty( Licensing::instance()->stored_licenses() ) ) {
			add_action( 'admin_notices', array( $this, 'render_license_aware_banner' ) );
		} else {
			add_action( 'admin_notices', array( $this, 'render_banner' ) );
		}

		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_banner_scripts' ) );
		add_action( 'admin_print_styles', array( $this, 'admin_banner_styles' ) );

		if ( Jetpack::state( 'network_nag' ) ) {
			add_action( 'network_admin_notices', array( $this, 'network_connect_notice' ) );
		}

		// Only fires immediately after plugin activation.
		if ( get_transient( 'activated_jetpack' ) ) {
			if (
				! \Jetpack_Options::get_option( 'has_seen_wc_connection_modal', false )
				&& in_array( 'woocommerce/woocommerce.php', apply_filters( 'active_plugins', Jetpack::get_active_plugins() ), true )
			) {
				wp_safe_redirect( Jetpack::admin_url( 'page=jetpack#/woo-setup' ) );
			} else {
				add_action( 'admin_enqueue_scripts', array( Jetpack::init(), 'activate_dialog' ) );
			}
			delete_transient( 'activated_jetpack' );
		}
	}

	/**
	 * Include the needed styles
	 */
	public function admin_banner_styles() {
		wp_enqueue_style(
			'jetpack-connection-banner',
			Assets::get_file_url_for_environment(
				'css/jetpack-connection-banner.min.css',
				'css/jetpack-connection-banner.css'
			),
			array(),
			JETPACK__VERSION
		);
	}

	/**
	 * Enqueues JavaScript for new connection banner.
	 *
	 * @since 4.4.0
	 */
	public static function enqueue_banner_scripts() {
		wp_enqueue_script(
			'jetpack-connection-banner-js',
			Assets::get_file_url_for_environment(
				'_inc/build/jetpack-connection-banner.min.js',
				'_inc/jetpack-connection-banner.js'
			),
			array( 'jquery' ),
			JETPACK__VERSION,
			true
		);

		wp_localize_script(
			'jetpack-connection-banner-js',
			'jp_banner',
			array(
				'ajax_url'              => admin_url( 'admin-ajax.php' ),
				'connectionBannerNonce' => wp_create_nonce( 'jp-connection-banner-nonce' ),
			)
		);
	}

	/**
	 * Enqueues JavaScript and CSS for the connection button.
	 *
	 * @since 7.7
	 */
	public static function enqueue_connect_button_scripts() {
		wp_enqueue_script(
			'jetpack-connect-button',
			Assets::get_file_url_for_environment(
				'_inc/build/connect-button.min.js',
				'_inc/connect-button.js'
			),
			array( 'jquery' ),
			JETPACK__VERSION,
			true
		);

		wp_enqueue_style(
			'jetpack-connect-button',
			Assets::get_file_url_for_environment(
				'css/jetpack-connect.min.css',
				'css/jetpack-connect.css'
			),
			array(),
			JETPACK__VERSION
		);

		$tracking = new Automattic\Jetpack\Tracking();
		$identity = $tracking->tracks_get_identity( get_current_user_id() );

		wp_localize_script(
			'jetpack-connect-button',
			'jpConnect',
			array(
				'buttonTextRegistering' => __( 'Loading...', 'jetpack' ),
				'connectUrl'            => Jetpack::admin_url( 'page=jetpack#/setup' ),
				'identity'              => $identity,
				'preFetchScript'        => plugins_url( '_inc/build/admin.js', JETPACK__PLUGIN_FILE ) . '?ver=' . JETPACK__VERSION,
			)
		);
	}

	/**
	 * Renders the new connection banner as of 4.4.0.
	 *
	 * @since 4.4.0
	 * @since 7.2   Copy and visual elements reduced to show the new focus of Jetpack on Security and Performance.
	 * @since 11.1  Adjusted the banner to Emerald style
	 */
	public function render_banner() {
		$jetpack_logo = new Logo();
		?>
		<div class="jp-connection-banner">
			<div class="jp-connection-banner__container-top-text">
				<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="0" fill="none" width="24" height="24"/><g><path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm1 15h-2v-2h2v2zm0-4h-2l-.5-6h3l-.5 6z"/></g></svg>
				<span>
					<?php esc_html_e( 'You’re almost done. Set up Jetpack to enable powerful security and performance tools for WordPress.', 'jetpack' ); ?>
				</span>
			</div>
			<?php
			if ( ! $this->force_display() ) :
				?>
					<span
						class="notice-dismiss jp-connection-banner__dismiss"
						title="<?php esc_attr_e( 'Dismiss this notice', 'jetpack' ); ?>">
					</span>

					<?php
				endif;
			?>
			<div class="jp-connection-banner__inner">
				<div class="jp-connection-banner__content">
					<div class="jp-connection-banner__logo">
						<?php echo $jetpack_logo->get_jp_emblem_larger(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					</div>
					<h2 class="jp-connection-banner__title"><?php esc_html_e( 'Simplify your site security and performance with Jetpack', 'jetpack' ); ?></h2>
					<div class="jp-connection-banner__columns">
						<div class="jp-connection-banner__text"><?php esc_html_e( 'Jetpack provides easy-to-use, comprehensive WordPress site security and backups, so you can focus on running your business.', 'jetpack' ); ?></div>
						<div class="jp-connection-banner__text"><?php esc_html_e( 'Jetpack’s performance features make your site lightning-fast, while also improving your SEO and giving your visitors a better experience.', 'jetpack' ); ?></div>
					</div>
					<div class="jp-connection-banner__footer">
						<div class="jp-connection-banner__text jp-connection-banner__text--caption"><?php jetpack_render_tos_blurb(); ?></div>
						<a id="jp-connect-button--alt" href="<?php echo esc_url( $this->build_connect_url_for_slide( '111' ) ); ?>" class="jp-banner-cta-button">
							<?php esc_html_e( 'Set up Jetpack', 'jetpack' ); ?>
						</a>
					</div>
				</div>
				<div class="jp-connection-banner__image-container">
					<img class="jp-connection-banner__image-background" src="<?php echo esc_url( plugins_url( 'images/jetpack-connection-banner-background.svg', JETPACK__PLUGIN_FILE ) ); ?>" />
					<picture>
						<source
							type="image/webp"
							srcset="<?php echo esc_url( plugins_url( 'images/jetpack-connection-image.webp', JETPACK__PLUGIN_FILE ) ); ?> 1x, <?php echo esc_url( plugins_url( 'images/jetpack-connection-image-2x.webp', JETPACK__PLUGIN_FILE ) ); ?> 2x">
						<img
							class="jp-connection-banner__image"
							srcset="<?php echo esc_url( plugins_url( 'images/jetpack-connection-image.png', JETPACK__PLUGIN_FILE ) ); ?> 1x, <?php echo esc_url( plugins_url( 'images/jetpack-connection-image-2x.png', JETPACK__PLUGIN_FILE ) ); ?> 2x"
							src="<?php echo esc_url( plugins_url( 'images/jetpack-connection-image.png', JETPACK__PLUGIN_FILE ) ); ?>"
							alt="">
					</picture>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders the license-away version of the connection banner.
	 *
	 * @since 9.0.0
	 * @since 11.1  Adjusted the banner to Emerald style
	 */
	public function render_license_aware_banner() {
		$jetpack_logo = new Logo();
		?>
		<div class="jp-connection-banner">
			<div class="jp-connection-banner__inner">
				<div class="jp-connection-banner__content">
					<div class="jp-connection-banner__logo">
						<?php echo $jetpack_logo->get_jp_emblem_larger(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					</div>
					<h2 class="jp-connection-banner__title jp-connection-banner__title--warning">
						<svg height="38" width="38" viewBox="0 0 24 24" class="jp-connection-banner__warning-icon">
							<g>
								<rect x="8" y="6" width="8" height="12" style="fill:#000000" />
								<path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm1 15h-2v-2h2v2zm0-4h-2l-.5-6h3l-.5 6z" style="fill:#eec74f"></path>
							</g>
						</svg>
						<?php esc_html_e( 'Finish setting up Jetpack', 'jetpack' ); ?>
					</h2>
					<div class="jp-connection-banner__text"><?php esc_html_e( "Thanks for purchasing a Jetpack subscription.\nThere’s just one more step to complete the installation.", 'jetpack' ); ?></div>
					<div class="jp-connection-banner__footer">
						<div class="jp-connection-banner__text jp-connection-banner__text--caption"><?php jetpack_render_tos_blurb(); ?></div>
						<a id="jp-connect-button--alt" href="<?php echo esc_url( $this->build_connect_url_for_slide( '111' ) ); ?>" class="jp-banner-cta-button">
							<?php esc_html_e( 'Set up Jetpack', 'jetpack' ); ?>
						</a>
					</div>
				</div>
				<div class="jp-connection-banner__image-container">
					<img class="jp-connection-banner__image-background" src="<?php echo esc_url( plugins_url( 'images/jetpack-connection-banner-background.svg', JETPACK__PLUGIN_FILE ) ); ?>" />
					<picture>
						<source
							type="image/webp"
							srcset="<?php echo esc_url( plugins_url( 'images/jetpack-connection-image.webp', JETPACK__PLUGIN_FILE ) ); ?> 1x, <?php echo esc_url( plugins_url( 'images/jetpack-connection-image-2x.webp', JETPACK__PLUGIN_FILE ) ); ?> 2x">
						<img
							class="jp-connection-banner__image"
							srcset="<?php echo esc_url( plugins_url( 'images/jetpack-connection-image.png', JETPACK__PLUGIN_FILE ) ); ?> 1x, <?php echo esc_url( plugins_url( 'images/jetpack-connection-image-2x.png', JETPACK__PLUGIN_FILE ) ); ?> 2x"
							src="<?php echo esc_url( plugins_url( 'images/jetpack-connection-image.png', JETPACK__PLUGIN_FILE ) ); ?>"
							alt="">
					</picture>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders the legacy network connection banner.
	 */
	public function network_connect_notice() {
		?>
		<div id="message" class="updated jetpack-message">
			<div class="squeezer">
				<h2>
					<?php
						echo wp_kses(
							__(
								'<strong>Jetpack is activated!</strong> Each site on your network must be connected individually by an admin on that site.',
								'jetpack'
							),
							array( 'strong' => array() )
						);
					?>
				</h2>
			</div>
		</div>
		<?php
	}
}
