<?php
namespace W3TC;



class Extension_NewRelic_Plugin {

	/**
	 * New Relic reject reason
	 *
	 * @var string
	 */
	var $newrelic_reject_reason = '';

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
		add_filter( 'w3tc_config_default_values', array(
				$this, 'w3tc_config_default_values' ) );

		$config = Dispatcher::config();
		// remainder only when extension is frontend-active
		if ( !$config->is_extension_active_frontend( 'newrelic' ) )
			return;

		if ( $this->_config->get_string( array( 'newrelic', 'monitoring_type' ) ) == 'browser' ) {
			Util_Bus::add_ob_callback( 'newrelic', array(
					$this, 'ob_callback_browser' ) );
		} else {
			require_once W3TC_LIB_NEWRELIC_DIR . '/NewRelicWrapper.php';

			$this->set_appname();

			if ( defined( 'DOING_CRON' ) && DOING_CRON )
				$this->background_task();

			Util_Bus::add_ob_callback( 'newrelic', array(
					$this, 'ob_callback_apm' ) );
		}

		add_filter( 'w3tc_footer_comment', array(
				$this,
				'w3tc_footer_comment'
			) );
	}

	public function w3tc_config_default_values( $default_values ) {
		$default_values['newrelic'] = array(
			'monitoring_type' => 'apm',
			'accept.logged_roles' => true,
			'accept.roles' => array( 'contributor' ),
			'use_php_function' => true,
			'cache_time' => 5,
			'include_rum' => true
		);

		return $default_values;
	}

	function ob_callback_browser( $buffer ) {
		$core = Dispatcher::component( 'Extension_NewRelic_Core' );
		$app = $core->get_effective_browser_application();
		if ( isset( $app['loader_script'] ) && $this->_can_add_tracker_script( $buffer ) ) {
			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $app['loader_script'], $buffer, 1 );
		}

		$buffer = str_replace('{w3tc_newrelic_reject_reason}',
			( $this->newrelic_reject_reason != '' ? sprintf( ' (%s)', $this->newrelic_reject_reason )
				: '' ),
			$buffer );

		return $buffer;
	}

	function ob_callback_apm( $buffer ) {
		if ( !$this->_can_add_tracker_script( $buffer ) ) {
			$this->disable_auto_rum();
		} else {
			if ( $this->_config->get_boolean( array( 'newrelic', 'include_rum' ) ) ) {
				$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui', '\\0' . \NewRelicWrapper::get_browser_timing_header(), $buffer, 1 );
				$buffer = preg_replace( '~<\\/body>~', \NewRelicWrapper::get_browser_timing_footer() . '\\0', $buffer, 1 );
			}
		}

		$buffer = str_replace('{w3tc_newrelic_reject_reason}',
			( $this->newrelic_reject_reason != '' ? sprintf( ' (%s)', $this->newrelic_reject_reason )
				: '' ),
			$buffer );

		return $buffer;
	}

	/**
	 * Mark current transaction as an background job in New Relic.
	 */
	function background_task() {
		\NewRelicWrapper::mark_as_background_job();
	}

	/**
	 * Disable auto rum for current transaction.
	 */
	function disable_auto_rum() {
		\NewRelicWrapper::disable_auto_rum();
	}

	function _can_add_tracker_script( $buffer ) {
		//
		$v = '';
		if ( preg_match('~^\s*<\?xml[^>]*>\s*<xsl:stylesheet~', $buffer, $v ) ) {
			$this->newrelic_reject_reason = __( 'XSL not tracked', 'w3-total-cache' );
			return false;
		}

		$reject_reason = apply_filters( 'w3tc_newrelic_should_disable_auto_rum', null );
		if ( !empty( $reject_reason ) ) {
			$this->newrelic_reject_reason =
				__( 'rejected by filter: ', 'w3-total-cache' ) . $reject_reason;
			return false;
		}


		/**
		 * Disable for AJAX so its not messed up
		 */
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			$this->newrelic_reject_reason = __( 'DOING_AJAX constant is defined', 'w3-total-cache' );

			return false;
		}


		/**
		 * Check for DONOTAUTORUM constant
		 */
		if ( defined( 'DONOTAUTORUM' ) && DONOTAUTORUM ) {
			$this->newrelic_reject_reason = __( 'DONOTAUTORUM constant is defined', 'w3-total-cache' );

			return false;
		}

		/**
		 * Check logged users roles
		 */
		if ( $this->_config->get_boolean( array( 'newrelic', 'accept.logged_roles' ) ) &&
			$this->_check_logged_in_role_not_allowed() ) {
			$this->newrelic_reject_reason = __( 'logged in role is rejected',
				'w3-total-cache' );

			return false;
		}

		return true;
	}

	/**
	 * Check if logged in user role is allowed to use New Relic Auto RUM
	 *
	 * @return boolean
	 */
	private function _check_logged_in_role_not_allowed() {
		$current_user = wp_get_current_user();

		if ( !is_user_logged_in() )
			return false;

		$roles = $this->_config->get_array( array( 'newrelic', 'accept.roles' ) );

		if ( empty( $roles ) || empty( $current_user->roles ) ||
			!is_array( $current_user->roles ) )
			return true;

		foreach ( $current_user->roles as $role ) {
			if ( in_array( $role, $roles ) )
				return false;
		}

		return true;
	}

	public function set_appname() {
		static $appname_set;
		if ( !$appname_set && ( $this->_config->get_boolean( array( 'newrelic', 'use_php_function' ) ) || Util_Environment::is_wpmu() ) ) {
			$appname_set = true;
			$service = Dispatcher::component( 'Extension_NewRelic_Service' );
			$appname = $service->get_effective_appname();

			$enable_xmit = $this->_config->get_boolean( array( 'newrelic', 'enable_xmit' ) );
			\NewRelicWrapper::set_appname( $appname, '', $enable_xmit );
		}
	}

	public function w3tc_footer_comment( $strings ) {
		$strings[] = sprintf(
			__( "Application Monitoring using New Relic%s", 'w3-total-cache' ),
			'{w3tc_newrelic_reject_reason}' );

		return $strings;
	}
}



$p = new Extension_NewRelic_Plugin();
$p->run();

if ( is_admin() ) {
	$p = new Extension_NewRelic_Plugin_Admin();
	$p->run();
}
