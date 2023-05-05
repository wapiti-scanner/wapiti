<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Assets\Logo;

/**
 * Jetpack connection dashboard widget.
 *
 * @package automattic/jetpack
 */
class Jetpack_Connection_Widget {
	/**
	 * Static instance
	 *
	 * @var Jetpack_Connection_Widget
	 */
	private static $instance = null;

	/**
	 * Intiialize the class by calling the setup static function.
	 *
	 * @return Jetpack_Connection_Widget
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Connection_Widget();
		}

		return self::$instance;
	}

	/**
	 * Jetpack_Connection_Widget constructor.
	 */
	public function __construct() {
		add_action( 'current_screen', array( $this, 'maybe_initialize_hooks' ) );
	}

	/**
	 * Will initialize hooks to display the new connection widget.
	 */
	public function maybe_initialize_hooks() {
		add_action( 'admin_print_styles', array( $this, 'admin_banner_styles' ) );
		add_action( 'wp_dashboard_setup', array( $this, 'wp_dashboard_setup' ) );
	}

	/**
	 * Sets up the Jetpack Connection Widget in the WordPress admin dashboard.
	 */
	public function wp_dashboard_setup() {
		if ( Jetpack_Options::get_option( 'dismissed_connection_banner' ) &&
			! Jetpack::is_connection_ready() ) {
			$widget_title = sprintf(
				__( 'Jetpack - Security, Backup, Speed & Growth', 'jetpack' )
			);

			wp_add_dashboard_widget(
				'jetpack_connection_widget',
				$widget_title,
				array( __CLASS__, 'connection_widget' )
			);
		}
	}

	/**
	 * Included the needed styles
	 */
	public function admin_banner_styles() {
		wp_enqueue_style(
			'jetpack-connection-widget',
			Assets::get_file_url_for_environment(
				'css/jetpack-connection-widget.min.css',
				'css/jetpack-connection-widget.css'
			),
			array(),
			JETPACK__VERSION
		);
	}

	/**
	 * Builds the connection url for the widget.
	 *
	 * @return string
	 */
	public static function build_connect_url() {
		$url = Jetpack::init()->build_connect_url(
			true,
			false,
			'unconnected-site-widget'
		);

		return add_query_arg( 'auth_approved', 'true', $url );
	}

	/**
	 * Load the widget
	 */
	public static function connection_widget() {
		$connect_url  = self::build_connect_url();
		$jetpack_logo = new Logo();
		?>
			<div class="jp-connection-widget">
				<div class="jp-connection-widget__logo">
					<?php echo $jetpack_logo->get_jp_emblem_larger(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</div>
				<img
					class="jp-connection-widget__image"
					src="<?php echo esc_url( plugins_url( 'images/dashboard-connection-widget-hero.png', JETPACK__PLUGIN_FILE ) ); ?>" />
				<p class="jp-connection-widget__heading"><?php esc_html_e( 'Finish setting up your site', 'jetpack' ); ?></p>
				<p class="jp-connection-widget__paragraph">
					<?php esc_html_e( 'Complete your setup to take advantage of security and performance features already installed by Jetpack.', 'jetpack' ); ?>
				</p>
				<p class="jp-connection-widget__tos-blurb">
					<?php jetpack_render_tos_blurb(); ?>
				</p>
				<p class="jp-connection_widget__button-container">
					<a class="jp-connection-widget__button" href="<?php echo esc_url( $connect_url ); ?>"><?php esc_html_e( 'Set up Jetpack for free', 'jetpack' ); ?></a>
				</p>
			</div>
		<?php
	}
}
