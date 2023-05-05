<?php
/**
 * Attachments sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

/**
 * Class to handle sync for attachments.
 */
class Attachments extends Module {
	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'attachments';
	}

	/**
	 * Initialize attachment action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		add_action( 'add_attachment', array( $this, 'process_add' ) );
		add_action( 'attachment_updated', array( $this, 'process_update' ), 10, 3 );
		add_action( 'jetpack_sync_save_update_attachment', $callable, 10, 2 );
		add_action( 'jetpack_sync_save_add_attachment', $callable, 10, 2 );
		add_action( 'jetpack_sync_save_attach_attachment', $callable, 10, 2 );
	}

	/**
	 * Handle the creation of a new attachment.
	 *
	 * @access public
	 *
	 * @param int $attachment_id ID of the attachment.
	 */
	public function process_add( $attachment_id ) {
		$attachment = get_post( $attachment_id );
		/**
		 * Fires when the client needs to sync an new attachment
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param int      Attachment ID.
		 * @param \WP_Post Attachment post object.
		 */
		do_action( 'jetpack_sync_save_add_attachment', $attachment_id, $attachment );
	}

	/**
	 * Handle updating an existing attachment.
	 *
	 * @access public
	 *
	 * @param int      $attachment_id     Attachment ID.
	 * @param \WP_Post $attachment_after  Attachment post object before the update.
	 * @param \WP_Post $attachment_before Attachment post object after the update.
	 */
	public function process_update( $attachment_id, $attachment_after, $attachment_before ) {
		// Check whether attachment was added to a post for the first time.
		if ( 0 === $attachment_before->post_parent && 0 !== $attachment_after->post_parent ) {
			/**
			 * Fires when an existing attachment is added to a post for the first time
			 *
			 * @since 1.6.3
			 * @since-jetpack 6.6.0
			 *
			 * @param int      $attachment_id     Attachment ID.
			 * @param \WP_Post $attachment_after  Attachment post object after the update.
			 */
			do_action( 'jetpack_sync_save_attach_attachment', $attachment_id, $attachment_after );
		} else {
			/**
			 * Fires when the client needs to sync an updated attachment
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.9.0
			 *
			 * @param int      $attachment_id     Attachment ID.
			 * @param \WP_Post $attachment_after  Attachment post object after the update.
			 *
			 * Previously this action was synced using jetpack_sync_save_add_attachment action.
			 */
			do_action( 'jetpack_sync_save_update_attachment', $attachment_id, $attachment_after );
		}
	}
}
