<?php
namespace W3TC;

class Generic_Plugin_AdminNotifications {

	private $_config;

	/**
	 *
	 *
	 * @var string
	 */
	private $_page;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		if ( Util_Admin::is_w3tc_admin_page() ) {
			add_action( 'admin_head', array(
					$this,
					'admin_head'
				) );

			add_action( 'w3tc_message_action_generic_support_us', array(
					$this,
					'w3tc_message_action_generic_support_us'
				) );
			add_action( 'w3tc_ajax_generic_support_us', array(
					$this,
					'w3tc_ajax_generic_support_us'
				) );

			add_action( 'w3tc_message_action_generic_edge', array(
					$this,
					'w3tc_message_action_generic_edge'
				) );
		}
	}

	/**
	 * Print JS required by the support nag.
	 */
	function admin_head() {
		$state = Dispatcher::config_state_master();

		// support us
		$day7 = 604800;
		$support_reminder =
			$state->get_integer( 'common.support_us_invitations' ) < 5 &&
			( $state->get_integer( 'common.install' ) <
			( time() - $day7 ) ) &&
			( $state->get_integer( 'common.next_support_us_invitation' ) <
			time() ) &&
			!$this->_config->get_boolean( 'common.tweeted' );

		if ( $support_reminder ) {
			$invitations = $state->get_integer( 'common.support_us_invitations' );

			if ( $invitations <= 0 ) {
				$delay = 259200;   // delay 3 days to day10
			} else {
				$delay = 2592000;
			}

			$state->set( 'common.next_support_us_invitation',
				time() + $delay );
			$state->set( 'common.support_us_invitations', $invitations + 1 );
			$state->save();

			do_action( 'w3tc_message_action_generic_support_us' );
		}
	}

	/**
	 * Display the support us nag
	 */
	public function w3tc_message_action_generic_support_us() {
		wp_enqueue_script( 'w3tc-generic_support_us',
			plugins_url( 'Generic_GeneralPage_View_ShowSupportUs.js', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	public function w3tc_ajax_generic_support_us() {
		$current_user = wp_get_current_user();
		wp_get_current_user();
		$email = $current_user->user_email;
		include W3TC_INC_DIR . '/lightbox/support_us.php';
	}



	/**
	 * Display the support us nag
	 */
	public function w3tc_message_action_generic_edge() {
		wp_enqueue_script( 'w3tc-generic_edge',
			plugins_url( 'Generic_GeneralPage_View_ShowEdge.js', W3TC_FILE ),
			array(), W3TC_VERSION );
	}
}
