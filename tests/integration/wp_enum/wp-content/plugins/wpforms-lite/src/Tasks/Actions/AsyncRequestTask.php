<?php

namespace WPForms\Tasks\Actions;

use WPForms\Tasks\Task;
use WPForms\Tasks\Meta;

/**
 * Class AsyncRequestTask is responsible to send information in the background.
 *
 * @since 1.7.5
 */
class AsyncRequestTask extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.7.5
	 */
	const ACTION = 'wpforms_process_async_request';

	/**
	 * Class constructor.
	 *
	 * @since 1.7.5
	 */
	public function __construct() {

		// Task functionality is needed on cron request only.
		if ( ! ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		parent::__construct( self::ACTION );

		$this->hooks();
	}

	/**
	 * Add hooks.
	 *
	 * @since 1.7.5
	 */
	private function hooks() {

		// Register the migrate action.
		add_action( self::ACTION, [ $this, 'process' ] );
	}


	/**
	 * Send usage tracking to the server.
	 *
	 * @since 1.7.5
	 *
	 * @param int $meta_id Action meta id.
	 */
	public static function process( $meta_id ) {

		$params = ( new Meta() )->get( $meta_id );

		if ( ! $params ) {
			return;
		}

		list( $url, $args ) = $params->data;

		wp_remote_get( $url, $args );
	}
}
