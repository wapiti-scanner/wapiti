<?php

namespace WPForms\Lite\Integrations\LiteConnect;

use WPForms\Integrations\LiteConnect\API;
use WPForms\Tasks\Meta;

/**
 * Class SendEntryTask.
 *
 * @since 1.7.4
 */
class SendEntryTask extends Integration {

	/**
	 * Task name.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const LITE_CONNECT_TASK = 'wpforms_lite_connect_send_entry';

	/**
	 * SendEntryTask constructor.
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
	 * Creates a task to submit the lite entry to the Lite Connect API via
	 * Action Scheduler.
	 *
	 * @since 1.7.4
	 *
	 * @param int    $form_id    The form ID.
	 * @param string $entry_data The entry data.
	 */
	public function create( $form_id, $entry_data ) {

		$action_id = wpforms()->get( 'tasks' )
			->create( self::LITE_CONNECT_TASK )
			->params( $form_id, $entry_data )
			->once( time() + wp_rand( 10, 60 ) * MINUTE_IN_SECONDS )
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
	 * Process the task to submit the entry to the Lite Connect API via
	 * Action Scheduler.
	 *
	 * @since 1.7.4
	 *
	 * @param int $meta_id The meta ID.
	 */
	public function process( $meta_id ) {

		// Load task data.
		$params = ( new Meta() )->get( (int) $meta_id );

		list( $form_id, $entry_data ) = $params->data;

		// Grab current access token. If site key or access token is not available, then it recreates the task to run later.
		$access_token = $this->get_access_token( $this->get_site_key() );

		if ( ! $access_token ) {
			$this->create( $form_id, $entry_data );

			return;
		}

		// Submit entry to the Lite Connect API.
		$response = ( new API() )->add_form_entry( $access_token, $form_id, $entry_data );

		if ( $response ) {
			$response = json_decode( $response, true );
		}

		if ( isset( $response['error'] ) && $response['error'] === 'Access token is invalid or expired.' ) {
			// Force to re-generate access token in case it is invalid.
			$this->get_access_token( $this->get_site_key(), true );
		}

		if ( ! empty( $response['error'] ) ) {
			wpforms_log(
				'Lite Connect: error submitting form entry (AS task)',
				[
					'response'   => $response,
					'entry_data' => $entry_data,
				],
				[
					'type'    => [ 'error' ],
					'form_id' => $form_id,
				]
			);
		}

		// Recreate the task if the request to the API fail for any reasons.
		if ( ! isset( $response['status'] ) || $response['status'] !== 'success' ) {
			$this->create( $form_id, $entry_data );

			return;
		}

		// Increase the entries count if the entry has been added successfully.
		$this->increase_entries_count( $form_id );
	}
}
