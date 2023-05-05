<?php
namespace W3TC;

/**
 * W3 Total Cache CDN Plugin
 */
class Cdnfsd_Plugin {
	/**
	 * Config
	 */
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		$engine = $this->_config->get_string( 'cdnfsd.engine' );

		if ( !Util_Environment::is_w3tc_pro( $this->_config ) || empty( $engine ) ) {
			return;
		}

		add_filter( 'w3tc_footer_comment', array(
				$this,
				'w3tc_footer_comment'
			) );

		add_action( 'w3tc_flush_all', array(
				'\W3TC\Cdnfsd_CacheFlush',
				'w3tc_flush_all'
			), 3000, 1 );
		add_action( 'w3tc_flush_post', array(
				'\W3TC\Cdnfsd_CacheFlush',
				'w3tc_flush_post'
			), 3000, 3 );
		add_action( 'w3tc_flushable_posts', '__return_true', 3000 );
		add_action( 'w3tc_flush_posts', array(
				'\W3TC\Cdnfsd_CacheFlush',
				'w3tc_flush_all'
			), 3000, 1 );
		add_action( 'w3tc_flush_url', array(
				'\W3TC\Cdnfsd_CacheFlush',
				'w3tc_flush_url'
			), 3000, 2 );
		add_filter( 'w3tc_flush_execute_delayed_operations', array(
				'\W3TC\Cdnfsd_CacheFlush',
				'w3tc_flush_execute_delayed_operations'
			), 3000 );

		Util_AttachToActions::flush_posts_on_actions();
	}

	public function w3tc_footer_comment( $strings ) {
		$config = Dispatcher::config();
		$via = $config->get_string('cdnfsd.engine');

		$strings[] = sprintf(
			__( 'Content Delivery Network Full Site Delivery via %s', 'w3-total-cache' ),
			( $via ? $via : 'N/A' ) );

		return $strings;
	}
}
