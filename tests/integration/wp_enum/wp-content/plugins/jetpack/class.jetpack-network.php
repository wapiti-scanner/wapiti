<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFilename
/**
 * Jetpack Network Manager class file.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets\Logo;
use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Connection\Tokens;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Waf\Brute_Force_Protection\Brute_Force_Protection_Shared_Functions;

/**
 * Used to manage Jetpack installation on Multisite Network installs
 *
 * SINGLETON: To use call Jetpack_Network::init()
 *
 * DO NOT USE ANY STATIC METHODS IN THIS CLASS!!!!!!
 *
 * @since 2.9
 */
class Jetpack_Network {

	/**
	 * Holds a static copy of Jetpack_Network for the singleton
	 *
	 * @since 2.9
	 * @var Jetpack_Network
	 */
	private static $instance = null;

	/**
	 * An instance of the connection manager object.
	 *
	 * @since 7.7
	 * @var Automattic\Jetpack\Connection\Manager
	 */
	private $connection;

	/**
	 * Name of the network wide settings
	 *
	 * @since 2.9
	 * @var string
	 */
	private $settings_name = 'jetpack-network-settings';

	/**
	 * Defaults for settings found on the Jetpack > Settings page
	 *
	 * @since 2.9
	 * @var array
	 */
	private $setting_defaults = array(
		'auto-connect'                 => 0,
		'sub-site-connection-override' => 1,
	);

	/**
	 * Constructor
	 *
	 * @since 2.9
	 */
	private function __construct() {
		require_once ABSPATH . '/wp-admin/includes/plugin.php'; // For the is_plugin... check.

		/**
		 * Sanity check to ensure the install is Multisite and we
		 * are in Network Admin
		 */
		if ( is_multisite() && is_network_admin() ) {
			add_action( 'network_admin_menu', array( $this, 'add_network_admin_menu' ) );
			add_action( 'network_admin_edit_jetpack-network-settings', array( $this, 'save_network_settings_page' ), 10, 0 );
			add_filter( 'admin_body_class', array( $this, 'body_class' ) );

			if ( isset( $_GET['page'] ) && 'jetpack' === $_GET['page'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is view logic.
				add_action( 'admin_init', array( $this, 'jetpack_sites_list' ) );
			}
		}

		/*
		 * Things that should only run on multisite
		 */
		if ( is_multisite() && is_plugin_active_for_network( 'jetpack/jetpack.php' ) ) {
			add_action( 'wp_before_admin_bar_render', array( $this, 'add_to_menubar' ) );
			add_filter( 'jetpack_disconnect_cap', array( $this, 'set_multisite_disconnect_cap' ) );

			/*
			 * If admin wants to automagically register new sites set the hook here
			 *
			 * This is a hacky way because xmlrpc is not available on wp_initialize_site
			 */
			if ( 1 === $this->get_option( 'auto-connect' ) ) {
				add_action( 'wp_initialize_site', array( $this, 'do_automatically_add_new_site' ) );
			}
		}
	}

	/**
	 * Sets a connection object.
	 *
	 * @param Automattic\Jetpack\Connection\Manager $connection the connection manager object.
	 */
	public function set_connection( Manager $connection ) {
		$this->connection = $connection;
	}

	/**
	 * Registers new sites upon creation
	 *
	 * @since 2.9
	 * @since 7.4.0 Uses a WP_Site object.
	 * @uses  wp_initialize_site
	 *
	 * @param WP_Site $site the WordPress site object.
	 **/
	public function do_automatically_add_new_site( $site ) {
		if ( is_a( $site, 'WP_Site' ) ) {
			$this->do_subsiteregister( $site->id );
		}
	}

	/**
	 * Adds .network-admin class to the body tag
	 * Helps distinguish network admin JP styles from regular site JP styles
	 *
	 * @since 2.9
	 *
	 * @param String $classes current assigned body classes.
	 * @return String amended class string.
	 */
	public function body_class( $classes ) {
		return trim( $classes ) . ' network-admin ';
	}

	/**
	 * Provides access to an instance of Jetpack_Network
	 *
	 * This is how the Jetpack_Network object should *always* be accessed
	 *
	 * @since 2.9
	 * @return Jetpack_Network
	 */
	public static function init() {
		if ( ! self::$instance || ! is_a( self::$instance, 'Jetpack_Network' ) ) {
			self::$instance = new Jetpack_Network();
		}

		return self::$instance;
	}

	/**
	 * Registers the Multisite admin bar menu item shortcut.
	 * This shortcut helps users quickly and easily navigate to the Jetpack Network Admin
	 * menu from anywhere in their network.
	 *
	 * @since 2.9
	 */
	public function register_menubar() {
		add_action( 'wp_before_admin_bar_render', array( $this, 'add_to_menubar' ) );
	}

	/**
	 * Runs when Jetpack is deactivated from the network admin plugins menu.
	 * Each individual site will need to have Jetpack::disconnect called on it.
	 * Site that had Jetpack individually enabled will not be disconnected as
	 * on Multisite individually activated plugins are still activated when
	 * a plugin is deactivated network wide.
	 *
	 * @since 2.9
	 **/
	public function deactivate() {
		// Only fire if in network admin.
		if ( ! is_network_admin() ) {
			return;
		}

		$sites = get_sites();

		foreach ( $sites as $s ) {
			switch_to_blog( $s->blog_id );
			$active_plugins = get_option( 'active_plugins' );

			/*
			 * If this plugin was activated in the subsite individually
			 * we do not want to call disconnect. Plugins activated
			 * individually (before network activation) stay activated
			 * when the network deactivation occurs
			 */
			if ( ! in_array( 'jetpack/jetpack.php', $active_plugins, true ) ) {
				Jetpack::disconnect();
				Jetpack_Options::delete_option( 'version' );
			}
			restore_current_blog();
		}
	}

	/**
	 * Adds a link to the Jetpack Network Admin page in the network admin menu bar.
	 *
	 * @since 2.9
	 **/
	public function add_to_menubar() {
		global $wp_admin_bar;
		// Don't show for logged out users or single site mode.
		if ( ! is_user_logged_in() || ! is_multisite() ) {
			return;
		}

		$wp_admin_bar->add_node(
			array(
				'parent' => 'network-admin',
				'id'     => 'network-admin-jetpack',
				'title'  => 'Jetpack',
				'href'   => $this->get_url( 'network_admin_page' ),
			)
		);
	}

	/**
	 * Returns various URL strings. Factory like
	 *
	 * $args can be a string or an array.
	 * If $args is an array there must be an element called name for the switch statement
	 *
	 * Currently supports:
	 * - subsiteregister: Pass array( 'name' => 'subsiteregister', 'site_id' => SITE_ID )
	 * - network_admin_page: Provides link to /wp-admin/network/JETPACK
	 * - subsitedisconnect: Pass array( 'name' => 'subsitedisconnect', 'site_id' => SITE_ID )
	 *
	 * @since 2.9
	 *
	 * @param Mixed $args URL parameters.
	 *
	 * @return String
	 **/
	public function get_url( $args ) {
		$url = null; // Default url value.

		if ( is_string( $args ) ) {
			$name = $args;
		} elseif ( is_array( $args ) ) {
			$name = $args['name'];
		} else {
			return $url;
		}

		switch ( $name ) {
			case 'subsiteregister':
				if ( ! isset( $args['site_id'] ) ) {
					break; // If there is not a site id present we cannot go further.
				}
				$url = network_admin_url(
					'admin.php?page=jetpack&action=subsiteregister&site_id='
					. $args['site_id']
				);
				break;

			case 'network_admin_page':
				$url = network_admin_url( 'admin.php?page=jetpack' );
				break;

			case 'subsitedisconnect':
				if ( ! isset( $args['site_id'] ) ) {
					break; // If there is not a site id present we cannot go further.
				}
				$url = network_admin_url(
					'admin.php?page=jetpack&action=subsitedisconnect&site_id='
					. $args['site_id']
				);
				break;
		}

		return $url;
	}

	/**
	 * Adds the Jetpack  menu item to the Network Admin area
	 *
	 * @since 2.9
	 */
	public function add_network_admin_menu() {
		$icon = ( new Logo() )->get_base64_logo();
		add_menu_page( 'Jetpack', 'Jetpack', 'jetpack_network_admin_page', 'jetpack', array( $this, 'wrap_network_admin_page' ), $icon, 3 );
		$jetpack_sites_page_hook    = add_submenu_page( 'jetpack', __( 'Jetpack Sites', 'jetpack' ), __( 'Sites', 'jetpack' ), 'jetpack_network_sites_page', 'jetpack', array( $this, 'wrap_network_admin_page' ) );
		$jetpack_settings_page_hook = add_submenu_page( 'jetpack', __( 'Settings', 'jetpack' ), __( 'Settings', 'jetpack' ), 'jetpack_network_settings_page', 'jetpack-settings', array( $this, 'wrap_render_network_admin_settings_page' ) );
		add_action( "admin_print_styles-$jetpack_sites_page_hook", array( 'Jetpack_Admin_Page', 'load_wrapper_styles' ) );
		add_action( "admin_print_styles-$jetpack_settings_page_hook", array( 'Jetpack_Admin_Page', 'load_wrapper_styles' ) );
		/**
		 * As jetpack_register_genericons is by default fired off a hook,
		 * the hook may have already fired by this point.
		 * So, let's just trigger it manually.
		 */
		require_once JETPACK__PLUGIN_DIR . '_inc/genericons.php';
		jetpack_register_genericons();
	}

	/**
	 * Provides functionality for the Jetpack > Sites page.
	 * Does not do the display!
	 *
	 * @since 2.9
	 */
	public function jetpack_sites_list() {
		Jetpack::init();

		if ( isset( $_GET['action'] ) ) {
			switch ( $_GET['action'] ) {
				case 'subsiteregister':
					check_admin_referer( 'jetpack-subsite-register' );
					Jetpack::log( 'subsiteregister' );

					// If no site_id, stop registration and error.
					if ( ! isset( $_GET['site_id'] ) || empty( $_GET['site_id'] ) ) {
						/**
						 * Log error to state cookie for display later.
						 *
						 * @todo Make state messages show on Jetpack NA pages
						 */
						Jetpack::state( 'missing_site_id', esc_html__( 'Site ID must be provided to register a sub-site.', 'jetpack' ) );
						break;
					}

					// Send data to register endpoint and retrieve shadow blog details.
					$result = $this->do_subsiteregister();
					$url    = $this->get_url( 'network_admin_page' );

					if ( is_wp_error( $result ) ) {
						$url = add_query_arg( 'action', 'connection_failed', $url );
					} else {
						$url = add_query_arg( 'action', 'connected', $url );
					}

					wp_safe_redirect( $url );
					exit;

				case 'subsitedisconnect':
					check_admin_referer( 'jetpack-subsite-disconnect' );
					Jetpack::log( 'subsitedisconnect' );

					if ( ! isset( $_GET['site_id'] ) || empty( $_GET['site_id'] ) ) {
						Jetpack::state( 'missing_site_id', esc_html__( 'Site ID must be provided to disconnect a sub-site.', 'jetpack' ) );
						break;
					}

					$this->do_subsitedisconnect();
					break;

				case 'connected':
				case 'connection_failed':
					add_action( 'jetpack_notices', array( $this, 'show_jetpack_notice' ) );
					break;
			}
		}
	}

	/**
	 * Set the disconnect capability for multisite.
	 *
	 * @param array $caps The capabilities array.
	 */
	public function set_multisite_disconnect_cap( $caps ) {
		// Can individual site admins manage their own connection?
		if ( ! is_super_admin() && ! $this->get_option( 'sub-site-connection-override' ) ) {
			/*
			 * We need to update the option name -- it's terribly unclear which
			 * direction the override goes.
			 *
			 * @todo: Update the option name to `sub-sites-can-manage-own-connections`
			 */
			return array( 'do_not_allow' );
		}

		return $caps;
	}

	/**
	 * Shows the Jetpack plugin notices.
	 */
	public function show_jetpack_notice() {
		if ( isset( $_GET['action'] ) && 'connected' === $_GET['action'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is view logic.
			$notice    = __( 'Site successfully connected.', 'jetpack' );
			$classname = 'updated';
		} elseif ( isset( $_GET['action'] ) && 'connection_failed' === $_GET['action'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is view logic.
			$notice    = __( 'Site connection failed!', 'jetpack' );
			$classname = 'error';
		}
		?>
		<div id="message" class="<?php echo esc_attr( $classname ); ?> jetpack-message jp-connect" style="display:block !important;">
			<p><?php echo esc_html( $notice ); ?></p>
		</div>
		<?php
	}

	/**
	 * Disconnect functionality for an individual site
	 *
	 * @since 2.9
	 * @see   Jetpack_Network::jetpack_sites_list()
	 *
	 * @param int $site_id the site identifier.
	 */
	public function do_subsitedisconnect( $site_id = null ) {
		if ( ! current_user_can( 'jetpack_disconnect' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Caller (i.e. `$this->jetpack_sites_list()`) should check.
		$site_id = ( $site_id === null ) ? ( isset( $_GET['site_id'] ) ? (int) $_GET['site_id'] : null ) : $site_id;
		switch_to_blog( $site_id );
		Jetpack::disconnect();
		restore_current_blog();
	}

	/**
	 * Registers a subsite with the Jetpack servers
	 *
	 * @since 2.9
	 * @todo  Break apart into easier to manage chunks that can be unit tested
	 * @see   Jetpack_Network::jetpack_sites_list();
	 *
	 * @param int $site_id the site identifier.
	 */
	public function do_subsiteregister( $site_id = null ) {
		if ( ! current_user_can( 'jetpack_disconnect' ) ) {
			return;
		}

		if ( ( new Status() )->is_offline_mode() ) {
			return;
		}

		// Figure out what site we are working on.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Caller (i.e. `$this->jetpack_sites_list()`) should check.
		$site_id = ( $site_id === null ) ? ( isset( $_GET['site_id'] ) ? (int) $_GET['site_id'] : null ) : $site_id;

		/*
		 * Here we need to switch to the subsite
		 * For the registration process we really only hijack how it
		 * works for an individual site and pass in some extra data here
		 */
		switch_to_blog( $site_id );

		add_filter( 'jetpack_register_request_body', array( $this, 'filter_register_request_body' ) );
		add_action( 'jetpack_site_registered_user_token', array( $this, 'filter_register_user_token' ) );

		// Save the secrets in the subsite so when the wpcom server does a pingback it
		// will be able to validate the connection.
		$result = $this->connection->register( 'subsiteregister' );

		if ( is_wp_error( $result ) || ! $result ) {
			restore_current_blog();
			return $result;
		}

		Jetpack::activate_default_modules( false, false, array(), false );

		restore_current_blog();
	}

	/**
	 * Receives the registration response token.
	 *
	 * @param Object $token the received token.
	 */
	public function filter_register_user_token( $token ) {
		$is_connection_owner = ! $this->connection->has_connected_owner();
		( new Tokens() )->update_user_token(
			get_current_user_id(),
			sprintf( '%s.%d', $token->secret, get_current_user_id() ),
			$is_connection_owner
		);
	}

	/**
	 * Filters the registration request body to include additional properties.
	 *
	 * @param array $properties standard register request body properties.
	 * @return array amended properties.
	 */
	public function filter_register_request_body( $properties ) {
		$blog_details = get_blog_details();

		$network = get_network();

		switch_to_blog( $network->blog_id );
		// The blog id on WordPress.com of the primary network site.
		$network_wpcom_blog_id = Jetpack_Options::get_option( 'id' );
		restore_current_blog();

		/**
		 * Both `state` and `user_id` need to be sent in the request, even though they are the same value.
		 * Connecting via the network admin combines `register()` and `authorize()` methods into one step,
		 * because we assume the main site is already authorized. `state` is used to verify the `register()`
		 * request, while `user_id()` is used to create the token in the `authorize()` request.
		 */
		return array_merge(
			$properties,
			array(
				'network_url'           => $this->get_url( 'network_admin_page' ),
				'network_wpcom_blog_id' => $network_wpcom_blog_id,
				'user_id'               => get_current_user_id(),

				/*
				 * Use the subsite's registration date as the site creation date.
				 *
				 * This is in contrast to regular standalone sites, where we use the helper
				 * `Jetpack::get_assumed_site_creation_date()` to assume the site's creation date.
				 */
				'site_created'          => $blog_details->registered,
			)
		);
	}

	/**
	 * A hook handler for adding admin pages and subpages.
	 */
	public function wrap_network_admin_page() {
		Jetpack_Admin_Page::wrap_ui( array( $this, 'network_admin_page' ) );
	}

	/**
	 * Handles the displaying of all sites on the network that are
	 * dis/connected to Jetpack
	 *
	 * @since 2.9
	 * @see   Jetpack_Network::jetpack_sites_list()
	 */
	public function network_admin_page() {
		global $current_site;
		$this->network_admin_page_header();

		$jp = Jetpack::init();

		// We should be, but ensure we are on the main blog.
		switch_to_blog( $current_site->blog_id );
		$main_active = $jp->is_connection_ready();
		restore_current_blog();

		// If we are in dev mode, just show the notice and bail.
		if ( ( new Status() )->is_offline_mode() ) {
			Jetpack::show_development_mode_notice();
			return;
		}

		/*
		 * Ensure the main blog is connected as all other subsite blog
		 * connections will feed off this one
		 */
		if ( ! $main_active ) {
			$data = array( 'url' => $jp->build_connect_url() );
			Jetpack::init()->load_view( 'admin/must-connect-main-blog.php', $data );

			return;
		}

		require_once __DIR__ . '/class.jetpack-network-sites-list-table.php';

		$network_sites_table = new Jetpack_Network_Sites_List_Table();
		echo '<div class="wrap"><h2>' . esc_html__( 'Sites', 'jetpack' ) . '</h2>';
		echo '<form method="post">';
		$network_sites_table->prepare_items();
		$network_sites_table->display();
		echo '</form></div>';
	}

	/**
	 * Stylized JP header formatting
	 *
	 * @since 2.9
	 */
	public function network_admin_page_header() {
		$is_connected = Jetpack::is_connection_ready();

		$data = array(
			'is_connected' => $is_connected,
		);
		Jetpack::init()->load_view( 'admin/network-admin-header.php', $data );
	}

	/**
	 * Fires when the Jetpack > Settings page is saved.
	 *
	 * @since 2.9
	 */
	public function save_network_settings_page() {

		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'jetpack-network-settings' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			// No nonce, push back to settings page.
			wp_safe_redirect(
				add_query_arg(
					array( 'page' => 'jetpack-settings' ),
					network_admin_url( 'admin.php' )
				)
			);
			exit();
		}

		// Try to save the Protect allow list before anything else, since that action can result in errors.
		$allow_list = isset( $_POST['global-allow-list'] ) ? filter_var( wp_unslash( $_POST['global-allow-list'] ) ) : '';
		$allow_list = str_replace( ' ', '', $allow_list );
		$allow_list = explode( PHP_EOL, $allow_list );
		$result     = Brute_Force_Protection_Shared_Functions::save_allow_list( $allow_list, true );
		if ( is_wp_error( $result ) ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'page'  => 'jetpack-settings',
						'error' => 'jetpack_protect_whitelist',
					),
					network_admin_url( 'admin.php' )
				)
			);
			exit();
		}

		/*
		 * Fields
		 *
		 * auto-connect - Checkbox for global Jetpack connection
		 * sub-site-connection-override - Allow sub-site admins to (dis)reconnect with their own Jetpack account
		 */
		$auto_connect = 0;
		if ( isset( $_POST['auto-connect'] ) ) {
			$auto_connect = 1;
		}

		$sub_site_connection_override = 0;
		if ( isset( $_POST['sub-site-connection-override'] ) ) {
			$sub_site_connection_override = 1;
		}

		$data = array(
			'auto-connect'                 => $auto_connect,
			'sub-site-connection-override' => $sub_site_connection_override,
		);

		update_site_option( $this->settings_name, $data );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => 'jetpack-settings',
					'updated' => 'true',
				),
				network_admin_url( 'admin.php' )
			)
		);
		exit();
	}

	/**
	 * A hook handler for adding admin pages and subpages.
	 */
	public function wrap_render_network_admin_settings_page() {
		Jetpack_Admin_Page::wrap_ui( array( $this, 'render_network_admin_settings_page' ) );
	}

	/**
	 * A hook rendering the admin settings page.
	 */
	public function render_network_admin_settings_page() {
		$this->network_admin_page_header();
		$options = wp_parse_args( get_site_option( $this->settings_name ), $this->setting_defaults );

		$modules      = array();
		$module_slugs = Jetpack::get_available_modules();
		foreach ( $module_slugs as $slug ) {
			$module           = Jetpack::get_module( $slug );
			$module['module'] = $slug;
			$modules[]        = $module;
		}

		usort( $modules, array( 'Jetpack', 'sort_modules' ) );

		if ( ! isset( $options['modules'] ) ) {
			$options['modules'] = $modules;
		}

		$data = array(
			'modules'                   => $modules,
			'options'                   => $options,
			'jetpack_protect_whitelist' => Brute_Force_Protection_Shared_Functions::format_allow_list(),
		);

		Jetpack::init()->load_view( 'admin/network-settings.php', $data );
	}

	/**
	 * Updates a site wide option
	 *
	 * @since 2.9
	 *
	 * @param string $key option name.
	 * @param mixed  $value option value.
	 *
	 * @return boolean
	 **/
	public function update_option( $key, $value ) {
		$options         = get_site_option( $this->settings_name, $this->setting_defaults );
		$options[ $key ] = $value;

		return update_site_option( $this->settings_name, $options );
	}

	/**
	 * Retrieves a site wide option
	 *
	 * @since 2.9
	 *
	 * @param string $name - Name of the option in the database.
	 **/
	public function get_option( $name ) {
		$options = get_site_option( $this->settings_name, $this->setting_defaults );
		$options = wp_parse_args( $options, $this->setting_defaults );

		if ( ! isset( $options[ $name ] ) ) {
			$options[ $name ] = null;
		}

		return $options[ $name ];
	}
}
