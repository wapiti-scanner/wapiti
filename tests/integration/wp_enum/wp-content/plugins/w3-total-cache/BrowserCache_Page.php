<?php
namespace W3TC;

class BrowserCache_Page extends Base_Page_Settings {
	protected $_page = 'w3tc_browsercache';

	public static function w3tc_ajax() {
		add_action( 'w3tc_ajax_browsercache_quick_reference', array(
			'\W3TC\BrowserCache_Page',
			'w3tc_ajax_browsercache_quick_reference' ) );
	}

	public static function w3tc_ajax_browsercache_quick_reference() {
		include  W3TC_DIR . '/BrowserCache_Page_View_QuickReference.php';
		exit();
	}

	function view() {
		$browsercache_enabled = $this->_config->get_boolean( 'browsercache.enabled' );
		$browsercache_last_modified = ( $this->_config->get_boolean( 'browsercache.cssjs.last_modified' ) && $this->_config->get_boolean( 'browsercache.html.last_modified' ) && $this->_config->get_boolean( 'browsercache.other.last_modified' ) );
		$browsercache_expires = ( $this->_config->get_boolean( 'browsercache.cssjs.expires' ) && $this->_config->get_boolean( 'browsercache.html.expires' ) && $this->_config->get_boolean( 'browsercache.other.expires' ) );
		$browsercache_cache_control = ( $this->_config->get_boolean( 'browsercache.cssjs.cache.control' ) && $this->_config->get_boolean( 'browsercache.html.cache.control' ) && $this->_config->get_boolean( 'browsercache.other.cache.control' ) );
		$browsercache_etag = ( $this->_config->get_boolean( 'browsercache.cssjs.etag' ) && $this->_config->get_boolean( 'browsercache.html.etag' ) && $this->_config->get_boolean( 'browsercache.other.etag' ) );
		$browsercache_w3tc = ( $this->_config->get_boolean( 'browsercache.cssjs.w3tc' ) && $this->_config->get_boolean( 'browsercache.html.w3tc' ) && $this->_config->get_boolean( 'browsercache.other.w3tc' ) );
		$browsercache_compression = ( $this->_config->get_boolean( 'browsercache.cssjs.compression' ) && $this->_config->get_boolean( 'browsercache.html.compression' ) && $this->_config->get_boolean( 'browsercache.other.compression' ) );
		$browsercache_brotli = ( $this->_config->get_boolean( 'browsercache.cssjs.brotli' ) && $this->_config->get_boolean( 'browsercache.html.brotli' ) && $this->_config->get_boolean( 'browsercache.other.brotli' ) );
		$browsercache_replace = ( $this->_config->get_boolean( 'browsercache.cssjs.replace' ) && $this->_config->get_boolean( 'browsercache.other.replace' ) );
		$browsercache_querystring = ( $this->_config->get_boolean( 'browsercache.cssjs.querystring' ) && $this->_config->get_boolean( 'browsercache.other.querystring' ) );
		$browsercache_update_media_qs = ( $this->_config->get_boolean( 'browsercache.cssjs.replace' ) || $this->_config->get_boolean( 'browsercache.other.replace' ) );
		$browsercache_nocookies =
			( $this->_config->get_boolean( 'browsercache.cssjs.nocookies' ) &&
			$this->_config->get_boolean( 'browsercache.other.nocookies' ) );

		$is_nginx = Util_Environment::is_nginx();

		include W3TC_INC_DIR . '/options/browsercache.php';
	}
}
