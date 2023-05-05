<?php
namespace W3TC;



class Generic_Page_General extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_general';

	private function to_human($bytes, $decimals = 2) {
		$size = array('B','kB','MB','GB','TB','PB','EB','ZB','YB');
		$factor = floor((strlen($bytes) - 1) / 3);
		return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$size[$factor];
	}

	/**
	 * General tab
	 *
	 * @return void
	 */
	function view() {
		if ( isset( $_REQUEST['view'] ) && $_REQUEST['view'] == 'purge_log' ) {
			$p = new Generic_Page_PurgeLog();
			$p->render_content();
			exit;
		}

		$current_user = wp_get_current_user();
		$config_master = $this->_config_master;
		/**
		 *
		 *
		 * @var $modules W3_ModuleStatus
		 */
		$modules = Dispatcher::component( 'ModuleStatus' );
		$pgcache_enabled = $modules->is_enabled( 'pgcache' );
		$dbcache_enabled = $modules->is_enabled( 'dbcache' );
		$objectcache_enabled = $modules->is_enabled( 'objectcache' );
		$browsercache_enabled = $modules->is_enabled( 'browsercache' );
		$minify_enabled = $modules->is_enabled( 'minify' );
		$cdn_enabled = $modules->is_enabled( 'cdn' );
		$varnish_enabled = $modules->is_enabled( 'varnish' );

		$enabled = $modules->plugin_is_enabled();

		$check_rules = Util_Rule::can_check_rules();
		$disc_enhanced_enabled = !( ! $check_rules || ( !$this->is_master() && Util_Environment::is_wpmu() && $config_master->get_string( 'pgcache.engine' ) != 'file_generic' ) );

		$can_empty_file = $modules->can_empty_file();

		$can_empty_varnish = $modules->can_empty_varnish();

		$cdn_mirror_purge = Cdn_Util::can_purge_all( $modules->get_module_engine( 'cdn' ) );


		$file_nfs = ( $this->_config->get_boolean( 'pgcache.file.nfs' ) || $this->_config->get_boolean( 'minify.file.nfs' ) );
		$file_locking = ( $this->_config->get_boolean( 'dbcache.file.locking' ) || $this->_config->get_boolean( 'objectcache.file.locking' ) || $this->_config->get_boolean( 'pgcache.file.locking' ) || $this->_config->get_boolean( 'minify.file.locking' ) );

		$licensing_visible = ( ( !Util_Environment::is_wpmu() || is_network_admin() ) &&
			!ini_get( 'w3tc.license_key' ) &&
			get_transient( 'w3tc_license_status' ) != 'host_valid' );
		$is_pro = Util_Environment::is_w3tc_pro( $this->_config );

		$custom_areas = apply_filters( "w3tc_settings_general_anchors", array() );
		include W3TC_INC_DIR . '/options/general.php';
	}
}
