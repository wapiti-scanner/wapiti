<?php

namespace WPForms\Tasks\Actions;

use WPForms\Tasks\Task;
use WPForms\Tasks\Meta;

/**
 * Class EntryEmailsTask is responsible for defining how to send emails,
 * when the form was submitted.
 *
 * @since 1.5.9
 */
class EntryEmailsTask extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.5.9
	 */
	const ACTION = 'wpforms_process_entry_emails';

	/**
	 * Class constructor.
	 *
	 * @since 1.5.9
	 */
	public function __construct() {

		parent::__construct( self::ACTION );

		$this->async();
	}

	/**
	 * Get the data from Tasks meta table, check/unpack it and
	 * send the email straight away.
	 *
	 * @since 1.5.9
	 * @since 1.5.9.3 Send immediately instead of calling \WPForms_Process::entry_email() method.
	 *
	 * @param int $meta_id ID for meta information for a task.
	 */
	public static function process( $meta_id ) {

		$task_meta = new Meta();
		$meta      = $task_meta->get( (int) $meta_id );

		// We should actually receive something.
		if ( empty( $meta ) || empty( $meta->data ) ) {
			return;
		}

		// We expect a certain number of params.
		if ( count( $meta->data ) !== 5 ) {
			return;
		}

		// We expect a certain meta data structure for this task.
		list( $to, $subject, $message, $headers, $attachments ) = $meta->data;

		// Let's do this NOW, finally.
		wp_mail( $to, $subject, $message, $headers, $attachments );
	}
}
