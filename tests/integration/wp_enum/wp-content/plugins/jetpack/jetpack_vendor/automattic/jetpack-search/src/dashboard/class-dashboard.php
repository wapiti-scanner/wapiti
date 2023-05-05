<?php
/**
 * A class that adds a search dashboard to wp-admin.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Search;

use Automattic\Jetpack\Admin_UI\Admin_Menu;
use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Tracking;
/**
 * Responsible for adding a search dashboard to wp-admin.
 *
 * @package Automattic\Jetpack\Search
 */
class Dashboard {
	/**
	 * Whether the class has been initialized
	 *
	 * @var boolean
	 */
	private static $initialized = false;
	/**
	 * Plan instance
	 *
	 * @var Automattic\Jetpack\Search\Plan
	 */
	protected $plan;

	/**
	 * Connection manager instance
	 *
	 * @var Automattic\Jetpack\Connection\Manager
	 */
	protected $connection_manager;

	/**
	 * Module_Control instance
	 *
	 * @var Automattic\Jetpack\Search\Module_Control
	 */
	protected $module_control;

	/**
	 * Priority for the dashboard menu
	 * For Jetpack sites: Jetpack uses 998 and 'Admin_Menu' uses 1000, so we need to use 999.
	 * For simple site: the value is overriden in a child class with value 100000 to wait for all menus to be registered.
	 *
	 * @var int
	 */
	protected $search_menu_priority = 999;

	/**
	 * Contructor
	 *
	 * @param Automattic\Jetpack\Search\Plan           $plan - Plan instance.
	 * @param Automattic\Jetpack\Connection\Manager    $connection_manager - Connection Manager instance.
	 * @param Automattic\Jetpack\Search\Module_Control $module_control - Module_Control instance.
	 */
	public function __construct( $plan = null, $connection_manager = null, $module_control = null ) {
		$this->plan               = $plan ? $plan : new Plan();
		$this->connection_manager = $connection_manager ? $connection_manager : new Connection_Manager( Package::SLUG );
		$this->module_control     = $module_control ? $module_control : new Module_Control( $this->plan );
		$this->plan->init_hooks();
	}

	/**
	 * Initialise hooks.
	 *
	 * We use the `config` package to initialize the search package, which ensures the package is
	 * only initialized once. However earlier versions of Jetpack would still forcely initialize the
	 * dashboard. As a result, there would be two `Search` submenus if we don't ensure the dashboard
	 * is initialized only once. So we use `$initialized` to ensure the class is only initialized once.
	 *
	 * Ref: https://github.com/Automattic/jetpack/pull/21888/files#diff-aae7d66951585fc55053a4d53b68552a41864d2c69aee900574ef4404b7ad5f7L42
	 */
	public function init_hooks() {
		if ( ! self::$initialized ) {
			self::$initialized = true;
			// Jetpack uses 998 and 'Admin_Menu' uses 1000.
			add_action( 'admin_menu', array( $this, 'add_wp_admin_submenu' ), $this->search_menu_priority );
			// Check if the site plan changed and deactivate module accordingly.
			add_action( 'current_screen', array( $this, 'check_plan_deactivate_search_module' ) );
		}
	}

	/**
	 * The page to be added to submenu
	 */
	public function add_wp_admin_submenu() {
		// Jetpack of version <= 10.5 would register `jetpack-search` submenu with its built-in search module.
		$this->remove_search_submenu_if_exists();

		if ( $this->should_add_search_submenu() ) {
			$page_suffix = Admin_Menu::add_menu(
				__( 'Jetpack Search', 'jetpack-search-pkg' ),
				_x( 'Search', 'product name shown in menu', 'jetpack-search-pkg' ),
				'manage_options',
				'jetpack-search',
				array( $this, 'render' ),
				100
			);
		} else {
			// always add the page, but hide it from the menu.
			$page_suffix = add_submenu_page(
				'',
				__( 'Jetpack Search', 'jetpack-search-pkg' ),
				_x( 'Search', 'product name shown in menu', 'jetpack-search-pkg' ),
				'manage_options',
				'jetpack-search',
				array( $this, 'render' )
			);
		}

		if ( $page_suffix ) {
			add_action( 'load-' . $page_suffix, array( $this, 'admin_init' ) );
		}
	}

	/**
	 * Override render funtion
	 */
	public function render() {
		?>
		<div id="jp-search-dashboard" class="jp-search-dashboard">
			<div class="hide-if-js"><?php esc_html_e( 'Your Jetpack Search dashboard requires JavaScript to function properly.', 'jetpack-search-pkg' ); ?></div>
		</div>
		<?php
	}

	/**
	 * Test whether we should show Search menu.
	 *
	 * @return {boolean} Show search sub menu or not.
	 */
	protected function should_add_search_submenu() {
		/**
		 * The filter allows to ommit adding a submenu item for Jetpack Search.
		 *
		 * @since 0.11.2
		 *
		 * @param boolean $should_add_search_submenu Default value is true.
		 */
		return apply_filters( 'jetpack_search_should_add_search_submenu', current_user_can( 'manage_options' ) );
	}

	/**
	 * Remove `jetpack-search` submenu page
	 */
	protected function remove_search_submenu_if_exists() {
		remove_submenu_page( 'jetpack', 'jetpack-search' );
	}

	/**
	 * Initialize the admin resources.
	 */
	public function admin_init() {
		add_action( 'admin_enqueue_scripts', array( $this, 'load_admin_scripts' ) );
	}

	/**
	 * Enqueue admin scripts.
	 */
	public function load_admin_scripts() {
		if ( $this->should_enqueue_tracking_script() ) {
			// Required for Analytics.
			Tracking::register_tracks_functions_scripts( true );
		}

		Assets::register_script(
			'jp-search-dashboard',
			'../../build/dashboard/jp-search-dashboard.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-search-pkg',
			)
		);
		Assets::enqueue_script( 'jp-search-dashboard' );

		// Add objects to be passed to the initial state of the app.
		// Use wp_add_inline_script instead of wp_localize_script, see https://core.trac.wordpress.org/ticket/25280.
		wp_add_inline_script(
			'jp-search-dashboard',
			( new Initial_State() )->render(),
			'before'
		);

		// Connection initial state.
		wp_add_inline_script(
			'jp-search-dashboard',
			Connection_Initial_State::render(),
			'before'
		);
	}

	/**
	 * Check if we should enqueue the tracking script.
	 */
	protected function should_enqueue_tracking_script() {
		return ! ( new Status() )->is_offline_mode() && $this->connection_manager->is_connected();
	}

	/**
	 * Deactivate search module if plan doesn't support search.
	 *
	 * @param WP_Screen $current_screen Creent screen object.
	 */
	public function check_plan_deactivate_search_module( $current_screen ) {
		// Only run on Jetpack admin pages.
		// The first two checks for current screen are cheap to run on every page.
		if (
			property_exists( $current_screen, 'base' ) &&
			strpos( $current_screen->base, 'jetpack_page_' ) !== false &&
			( ! $this->plan->supports_search() || $this->plan->must_upgrade() )
		) {
			$this->module_control->deactivate();
		}
	}

}
