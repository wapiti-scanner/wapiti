<?php
/**
 * A class that adds a wordads dashboard to wp-admin.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\WordAds;

use Automattic\Jetpack\Admin_UI\Admin_Menu;
use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Tracking;
/**
 * Responsible for adding a WordAds dashboard to wp-admin.
 *
 * @package Automattic\Jetpack\WordAds
 */
class Dashboard {

	/**
	 * Connection manager instance
	 *
	 * @var Automattic\Jetpack\Connection\Manager
	 */
	protected $connection_manager;

	/**
	 * Contructor
	 *
	 * @param Automattic\Jetpack\Connection\Manager $connection_manager - Connection Manager instance.
	 */
	public function __construct( $connection_manager = null ) {
		$this->connection_manager = $connection_manager ? $connection_manager : new Connection_Manager( Package::SLUG );
	}

	/**
	 * Initialise hooks
	 */
	public function init_hooks() {
		add_action( 'admin_menu', array( $this, 'add_wp_admin_submenu' ), 999 );
	}

	/**
	 * The page to be added to submenu
	 */
	public function add_wp_admin_submenu() {
		if ( ! $this->should_add_wordads_submenu() ) {
			return;
		}

		$page_suffix = Admin_Menu::add_menu(
			__( 'WordAds Settings', 'jetpack-wordads' ),
			_x( 'WordAds', 'product name shown in menu', 'jetpack-wordads' ),
			'manage_options',
			'jetpack-wordads',
			array( $this, 'render' ),
			100
		);

		add_action( 'load-' . $page_suffix, array( $this, 'admin_init' ) );
	}

	/**
	 * Override render funtion
	 */
	public function render() {
		?>
		<div id="jp-wordads-dashboard" class="jp-wordads-dashboard">
			<div class="hide-if-js"><?php esc_html_e( 'Your WordAds dashboard requires JavaScript to function properly.', 'jetpack-wordads' ); ?></div>
		</div>
		<?php
	}

	/**
	 * Test whether we should show Search menu.
	 *
	 * @return {boolean} Show search sub menu or not.
	 */
	protected function should_add_wordads_submenu() {
		/**
		 * The filter allows to ommit adding a submenu item for WordAds.
		 *
		 * @since 0.1.0
		 *
		 * @param boolean $should_add_wordads_submenu Default value is true.
		 */
		return apply_filters( 'jetpack_wordads_should_add_wordads_submenu', current_user_can( 'manage_options' ) );
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
		if ( ! ( new Status() )->is_offline_mode() && $this->connection_manager->is_connected() ) {
			// Required for Analytics.
			Tracking::register_tracks_functions_scripts( true );
		}

		Assets::register_script(
			'jp-wordads-dashboard',
			'../../build/dashboard/jp-wordads-dashboard.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-wordads',
			)
		);
		Assets::enqueue_script( 'jp-wordads-dashboard' );

		// Add objects to be passed to the initial state of the app.
		// Use wp_add_inline_script instead of wp_localize_script, see https://core.trac.wordpress.org/ticket/25280.
		wp_add_inline_script(
			'jp-wordads-dashboard',
			( new Initial_State() )->render(),
			'before'
		);
	}
}
