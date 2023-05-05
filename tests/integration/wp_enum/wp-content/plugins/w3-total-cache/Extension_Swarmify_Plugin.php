<?php
namespace W3TC;



class Extension_Swarmify_Plugin {
	private $reject_reason = '';
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
		if ( !$config->is_extension_active_frontend( 'swarmify' ) )
			return;

		if ($this->_active()) {
			Util_Bus::add_ob_callback( 'swarmify', array(
					$this,
					'ob_callback'
				) );
		}

		add_filter( 'w3tc_footer_comment', array(
				$this,
				'w3tc_footer_comment'
			) );
	}

	public function w3tc_config_default_values( $default_values ) {
		$default_values['swarmify'] = array(
			'reject.logged' => false,
			'api_key' => '',
			'handle.htmlvideo' => true,
			'handle.jwplayer' => true
		);

		return $default_values;
	}

	function ob_callback( $buffer ) {
		$c = $this->_config;
		$api_key = $c->get_string( array( 'swarmify', 'api_key' ) );
		$api_key = preg_replace( '~[^0-9a-zA-Z-]~', '', $api_key );   // make safe

		$bootstrap_required = false;

		if ( $c->get_boolean( array( 'swarmify', 'handle.htmlvideo' ) ) ) {
			$count = 0;
			$buffer = preg_replace( '~<video([^<>]+)>~i', '<swarmvideo\\1>',
				$buffer, -1, $count );

			if ( $count ) {
				$buffer = preg_replace( '~<\\/video>~', '</swarmvideo>', $buffer );
				$bootstrap_required = true;
			}
		}

		if ( $c->get_boolean( array( 'swarmify', 'handle.jwplayer' ) ) ) {
			$count = 0;
			$buffer = preg_replace( '~jwplayer\s*\\(([^)]+)\\)\s*\\.setup\\(~', 'swarmify.jwPlayerEmbed(\\1, ',
				$buffer, -1, $count );

			if ( $count )
				$bootstrap_required = true;
		}

		// add bootstrap swarmify script if there are really any videos on page
		if ( $bootstrap_required ) {
			$loader_script = '<script>' .
				'var swarmoptions = {swarmcdnkey: "' . $api_key . '"};</script>' .
				'<script src="//assets.swarmcdn.com/cross/swarmcdn.js"></script>';

			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $loader_script, $buffer, 1 );
		}

		return $buffer;
	}


	function _active() {
		$reject_reason = apply_filters( 'w3tc_swarmify_active', null );
		if ( !empty( $reject_reason ) ) {
			$this->reject_reason =
				__( 'rejected by filter: ', 'w3-total-cache' ) . $reject_reason;
			return false;
		}


		/**
		 * Disable for AJAX so its not messed up
		 */
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			$this->reject_reason = __( 'DOING_AJAX constant is defined', 'w3-total-cache' );
			return false;
		}

		if ( defined( 'WP_ADMIN' ) ) {
			$this->reject_reason = __( 'WP_ADMIN page', 'w3-total-cache' );
			return false;
		}

		/**
		 * Check logged users
		 */
		if ( $this->_config->get_boolean( array( 'swarmify', 'reject.logged' ) ) &&
			is_user_logged_in() ) {
			$this->reject_reason = __( 'logged in user rejected',
				'w3-total-cache' );

			return false;
		}

		return true;
	}

	public function w3tc_footer_comment( $strings ) {
		$append = ( $this->reject_reason != '' ) ?
			sprintf( ' (%s)', $this->reject_reason ) : ' active';
		$strings[] = sprintf(
			__( "Swarmify%s", 'w3-total-cache' ),
			$append );

		return $strings;
	}
}



$p = new Extension_Swarmify_Plugin();
$p->run();

if ( is_admin() ) {
	$p = new Extension_Swarmify_Plugin_Admin();
	$p->run();
}
