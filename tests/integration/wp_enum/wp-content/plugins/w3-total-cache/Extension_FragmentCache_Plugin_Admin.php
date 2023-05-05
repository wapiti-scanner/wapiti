<?php
namespace W3TC;



class Extension_FragmentCache_Plugin_Admin {
	private $_config = null;


	/**
	 * Called from outside, to get extension's details
	 */
	static public function w3tc_extensions( $extensions, $config ) {
		$requirements = array();

		$extensions['fragmentcache'] = array (
			'name' => 'Fragment Cache',
			'author' => 'W3 EDGE',
			'description' => 'Caching of page fragments.',
			'author_uri' => 'https://www.w3-edge.com/',
			'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'fragmentcache',
			'pro_feature' => true,
			'pro_excerpt' => __( 'Increase the performance of dynamic sites that cannot benefit from the caching of entire pages.', 'w3-total-cache' ),
			'pro_description' => array(
				__( 'Fragment caching extends the core functionality of WordPress by enabling caching policies to be set on groups of objects that are cached. This allows you to optimize various elements in themes and plugins to use caching to save resources and reduce response times. You can also use caching methods like Memcached or Redis (for example) to scale. Instructions for use are available in the FAQ available under the help menu. This feature also gives you control over the caching policies by the group as well as visibility into the configuration by extending the WordPress Object API with additional functionality.', 'w3-total-cache' ),
				__( 'Fragment caching is a powerful, but advanced feature. If you need help, take a look at our premium support, customization and audit services.', 'w3-total-cache' ),
			),
			'settings_exists' => true,
			'version' => '1.0',
			'enabled' => empty( $requirements ),
			'requirements' => implode( ', ', $requirements ),
			'active_frontend_own_control' => true,
			'path' => 'w3-total-cache/Extension_FragmentCache_Plugin.php'
		);

		return $extensions;
	}

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		add_filter( 'w3tc_objectcache_addin_required', array(
				$this, 'w3tc_objectcache_addin_required' ) );

		add_action( 'w3tc_environment_fix_on_event', array(
				'\W3TC\Extension_FragmentCache_Environment', 'fix_on_event' ),
			10, 2 );
		add_action( 'w3tc_deactivate_extension_fragmentcache', array(
				'\W3TC\Extension_FragmentCache_Environment', 'deactivate_extension' ) );

		add_filter( 'w3tc_admin_menu', array( $this, 'w3tc_admin_menu' ) );
		add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );
		add_filter( 'w3tc_extension_plugin_links_fragmentcache',
			array( $this, 'w3tc_extension_plugin_links' ) );
		add_action( 'w3tc_settings_page-w3tc_fragmentcache',
			array( $this, 'w3tc_settings_page_w3tc_fragmentcache' ) );

		add_action( 'admin_init_w3tc_general', array(
				'\W3TC\Extension_FragmentCache_GeneralPage',
				'admin_init_w3tc_general'
			) );

		add_action( 'w3tc_config_save', array( $this, 'w3tc_config_save' ), 10, 1 );

		add_filter( 'w3tc_usage_statistics_summary_from_history', array(
				$this, 'w3tc_usage_statistics_summary_from_history' ), 10, 2 );
	}



	public function w3tc_objectcache_addin_required( $addin_required ) {
		if ( $this->_config->is_extension_active_frontend( 'fragmentcache' ) ) {
			return true;
		}

		return $addin_required;
	}



	public function w3tc_extension_plugin_links( $links ) {
		$links = array();
		$links[] = '<a class="edit" href="' .
			esc_attr( Util_Ui::admin_url( 'admin.php?page=w3tc_fragmentcache' ) ) .
			'">'. __( 'Settings' ).'</a>';

		return $links;
	}




	public function w3tc_admin_menu( $menu ) {
		$menu['w3tc_fragmentcache'] = array(
			'page_title' => __( 'Fragment Cache', 'w3-total-cache' ),
			'menu_text' => '<span class="w3tc_menu_item_pro">' .
			__( 'Fragment Cache', 'w3-total-cache' ) . '</span>',
			'visible_always' => false,
			'order' => 1100
		);

		return $menu;
	}



	public function w3tc_admin_bar_menu( $menu_items ) {
		if ( $this->_config->is_extension_active_frontend( 'fragmentcache' ) ) {
			$menu_items['20510.fragmentcache'] = array(
				'id' => 'w3tc_flush_fragmentcache',
				'parent' => 'w3tc_flush',
				'title' => __( 'Fragment Cache: All Fragments', 'w3-total-cache' ),
				'href' => wp_nonce_url( admin_url(
						'admin.php?page=w3tc_dashboard&amp;w3tc_flush_fragmentcache' ), 'w3tc' )
			);
		}

		return $menu_items;
	}



	public function w3tc_settings_page_w3tc_fragmentcache() {
		$v = new Extension_FragmentCache_Page();
		$v->render_content();
	}



	public function w3tc_config_save( $config ) {
		// frontend activity
		$engine = $config->get_string( array( 'fragmentcache', 'engine' ) );

		$is_frontend_active = ( !empty( $engine ) &&
			Util_Environment::is_w3tc_pro( $config ) );

		$config->set_extension_active_frontend( 'fragmentcache',
			$is_frontend_active );
	}



	public function w3tc_usage_statistics_summary_from_history( $summary, $history ) {
		if ( !$this->_config->is_extension_active_frontend( 'fragmentcache' ) ) {
			return $summary;
		}

		// memcached servers
		$c = Dispatcher::config();
		if ( $c->get_string( array( 'fragmentcache', 'engine' ) ) == 'memcached' ) {
			$summary['memcached_servers']['fragmentcache'] = array(
				'servers' => $c->get_array( array( 'fragmentcache', 'memcached.servers' ) ),
				'username' => $c->get_string( array( 'fragmentcache', 'memcached.username' ) ),
				'password' => $c->get_string( array( 'fragmentcache', 'memcached.password' ) ),
				'name' => __( 'Fragment Cache', 'w3-total-cache' )
			);
		} elseif ( $c->get_string( array( 'fragmentcache', 'engine' ) ) == 'redis' ) {
			$summary['redis_servers']['fragmentcache'] = array(
				'servers' => $c->get_array( array( 'fragmentcache', 'redis.servers' ) ),
				'username' => $c->get_boolean( array( 'fragmentcache', 'redis.username' ) ),
				'dbid' => $c->get_integer( array( 'fragmentcache', 'redis.dbid' ) ),
				'password' => $c->get_string( array( 'fragmentcache', 'redis.password' ) ),
				'name' => __( 'Fragment Cache', 'w3-total-cache' )
			);
		}

		// counters
		$fragmentcache_calls_total = Util_UsageStatistics::sum( $history,
			'fragmentcache_calls_total' );
		$fragmentcache_calls_hits = Util_UsageStatistics::sum( $history,
			'fragmentcache_calls_hits' );

		$summary['fragmentcache'] = array(
			'calls_total' => Util_UsageStatistics::integer(
				$fragmentcache_calls_total ),
			'calls_per_second' => Util_UsageStatistics::value_per_period_seconds(
				$fragmentcache_calls_total, $summary ),
			'hit_rate' => Util_UsageStatistics::percent(
				$fragmentcache_calls_total, $fragmentcache_calls_total )
		);

		return $summary;
	}
}
