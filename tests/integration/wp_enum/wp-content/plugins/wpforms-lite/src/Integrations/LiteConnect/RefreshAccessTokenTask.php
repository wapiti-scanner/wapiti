<?php

namespace WPForms\Integrations\LiteConnect;

/**
 * Class RefreshAccessTokenTask.
 *
 * @since 1.7.4
 */
class RefreshAccessTokenTask extends Integration {

	/**
	 * Task name.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const LITE_CONNECT_TASK = 'wpforms_lite_connect_refresh_access_token';

	/**
	 * RefreshAccessTokenTask constructor.
	 *
	 * @since 1.7.4
	 */
	public function __construct() {

		parent::__construct();

		$this->hooks();
	}

	/**
	 * Initialize the hooks.
	 *
	 * @since 1.7.4
	 */
	private function hooks() {

		// Process the tasks as needed.
		add_action( self::LITE_CONNECT_TASK, [ $this, 'process' ] );
	}

	/**
	 * Creates a task to refresh the Lite Connect access token via Action Scheduler.
	 *
	 * @since 1.7.4
	 */
	public function create() {

		$action_id = wpforms()->get( 'tasks' )
			->create( self::LITE_CONNECT_TASK )
			->once( time() + 6 * DAY_IN_SECONDS )
			->register();

		if ( $action_id === null ) {
			wpforms_log(
				'Lite Connect: error creating the AS task',
				[
					'task' => self::LITE_CONNECT_TASK,
				],
				[ 'type' => [ 'error' ] ]
			);
		}
	}

	/**
	 * Process the task to regenerate the access token.
	 *
	 * @since 1.7.4
	 */
	public function process() {

		$this->get_access_token( $this->get_site_key(), true );
	}
}
