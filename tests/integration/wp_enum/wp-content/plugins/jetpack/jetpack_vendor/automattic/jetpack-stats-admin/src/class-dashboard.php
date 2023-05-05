<?php
/**
 * A class that adds a stats dashboard to wp-admin.
 *
 * @package automattic/jetpack-stats-admin
 */

namespace Automattic\Jetpack\Stats_Admin;

use Automattic\Jetpack\Admin_UI\Admin_Menu;
use Automattic\Jetpack\Stats\Options as Stats_Options;

/**
 * Responsible for adding a stats dashboard to wp-admin.
 *
 * @package jetpack-stats-admin
 */
class Dashboard {
	/**
	 * Whether the class has been initialized
	 *
	 * @var boolean
	 */
	private static $initialized = false;

	/**
	 * Priority for the dashboard menu
	 * For Jetpack sites: Jetpack uses 998 and 'Admin_Menu' uses 1000, so we need to use 999.
	 * For simple site: the value is overriden in a child class with value 100000 to wait for all menus to be registered.
	 *
	 * @var int
	 */
	protected $menu_priority = 999;

	/**
	 * Init Stats dashboard.
	 */
	public static function init() {
		if ( ! self::$initialized ) {
			self::$initialized = true;
			( new self() )->init_hooks();
		}
	}

	/**
	 * Initialize the hooks.
	 */
	public function init_hooks() {
		self::$initialized = true;
		// Jetpack uses 998 and 'Admin_Menu' uses 1000.
		add_action( 'admin_menu', array( $this, 'add_wp_admin_submenu' ), $this->menu_priority );
	}

	/**
	 * The page to be added to submenu
	 */
	public function add_wp_admin_submenu() {
		$page_suffix = Admin_Menu::add_menu(
			__( 'Stats App', 'jetpack-stats-admin' ),
			_x( 'Stats App', 'product name shown in menu', 'jetpack-stats-admin' ),
			'manage_options',
			'jetpack-stats-app',
			array( $this, 'render' ),
			100
		);

		if ( $page_suffix ) {
			add_action( 'load-' . $page_suffix, array( $this, 'admin_init' ) );
		}
	}

	/**
	 * Override render funtion
	 */
	public function render() {
		// Record the number of views of the stats dashboard on the initial several loads for the purpose of showing feedback notice.
		$views = intval( Stats_Options::get_option( 'views' ) ) + 1;
		if ( $views <= Notices::VIEWS_TO_SHOW_FEEDBACK ) {
			Stats_Options::set_option( 'views', $views );
		}

		?>
		<div id="wpcom" class="jp-stats-dashboard" style="min-height: calc(100vh - 100px);">
			<div class="hide-if-js"><?php esc_html_e( 'Your Jetpack Stats dashboard requires JavaScript to function properly.', 'jetpack-stats-admin' ); ?></div>
			<div class="hide-if-no-js" style="height: 100%">
				<img
					class="jp-stats-dashboard-loading-spinner"
					width="32"
					height="32"
					style="position: absolute; left: 50%; top: 50%;"
					alt=<?php echo esc_attr( __( 'Loading', 'jetpack-stats-admin' ) ); ?>
					src="//en.wordpress.com/i/loading/loading-64.gif"
				/>
			</div>
		</div>
		<script>
			jQuery(document).ready(function($) {
				// Load SVG sprite.
				$.get("https://widgets.wp.com/odyssey-stats/common/gridicons-506499ddac13811fee8e.svg", function(data) {
					var div = document.createElement("div");
					div.innerHTML = new XMLSerializer().serializeToString(data.documentElement);
					div.style = 'display: none';
					document.body.insertBefore(div, document.body.childNodes[0]);
				});
				// we intercept on all anchor tags and change it to hashbang style.
				$("#wpcom").on('click', 'a', function (e) {
					const link = e && e.currentTarget && e.currentTarget.attributes && e.currentTarget.attributes.href && e.currentTarget.attributes.href.value;
					if( link && link.startsWith( '/stats' ) ) {
						location.hash = `#!${link}`;
						return false;
					}
				});
			});
		</script>
		<?php
	}

	/**
	 * Initialize the admin resources.
	 */
	public function admin_init() {
		add_action( 'admin_enqueue_scripts', array( $this, 'load_admin_scripts' ) );
	}

	/**
	 * Load the admin scripts.
	 */
	public function load_admin_scripts() {
		( new Odyssey_Assets() )->load_admin_scripts( 'jp-stats-dashboard', 'build.min', array( 'config_variable_name' => 'jetpackStatsOdysseyAppConfigData' ) );
	}
}
