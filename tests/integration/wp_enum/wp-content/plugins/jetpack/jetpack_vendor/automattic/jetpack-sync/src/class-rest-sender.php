<?php
/**
 * Sync package.
 *
 * @package  automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use WP_Error;

/**
 * This class will handle checkout of Sync queues for REST Endpoints.
 *
 * @since 1.23.1
 */
class REST_Sender {

	/**
	 * Items pending send.
	 *
	 * @var array
	 */
	public $items = array();

	/**
	 * Checkout objects from the queue
	 *
	 * @param string $queue_name   Name of Queue.
	 * @param int    $number_of_items Number of Items.
	 * @param array  $args          arguments.
	 *
	 * @return array|WP_Error
	 */
	public function queue_pull( $queue_name, $number_of_items, $args ) {
		$queue = new Queue( $queue_name );

		if ( 0 === $queue->size() ) {
			return new WP_Error( 'queue_size', 'The queue is empty and there is nothing to send', 400 );
		}

		$sender = Sender::get_instance();

		// try to give ourselves as much time as possible.
		set_time_limit( 0 );

		if ( ! empty( $args['pop'] ) ) {
			$buffer = new Queue_Buffer( 'pop', $queue->pop( $number_of_items ) );
		} else {
			// let's delete the checkin state.
			if ( $args['force'] ) {
				$queue->unlock();
			}
			$buffer = $this->get_buffer( $queue, $number_of_items );
		}
		// Check that the $buffer is not checkout out already.
		if ( is_wp_error( $buffer ) ) {
			return new WP_Error( 'buffer_open', "We couldn't get the buffer it is currently checked out", 400 );
		}

		if ( ! is_object( $buffer ) ) {
			return new WP_Error( 'buffer_non-object', 'Buffer is not an object', 400 );
		}

		$encode = isset( $args['encode'] ) ? $args['encode'] : true;

		Settings::set_is_syncing( true );
		list( $items_to_send, $skipped_items_ids ) = $sender->get_items_to_send( $buffer, $encode );
		Settings::set_is_syncing( false );

		return array(
			'buffer_id'      => $buffer->id,
			'items'          => $items_to_send,
			'skipped_items'  => $skipped_items_ids,
			'codec'          => $encode ? $sender->get_codec()->name() : null,
			'sent_timestamp' => time(),
		);
	}

	/**
	 * Adds Sync items to local property.
	 */
	public function jetpack_sync_send_data_listener() {
		foreach ( func_get_args()[0] as $key => $item ) {
			$this->items[ $key ] = $item;
		}
	}

	/**
	 * Check out a buffer of full sync actions.
	 *
	 * @return array Sync Actions to be returned to requestor
	 */
	public function immediate_full_sync_pull() {
		// try to give ourselves as much time as possible.
		set_time_limit( 0 );

		$original_send_data_cb = array( 'Automattic\Jetpack\Sync\Actions', 'send_data' );
		$temp_send_data_cb     = array( $this, 'jetpack_sync_send_data_listener' );

		Sender::get_instance()->set_enqueue_wait_time( 0 );
		remove_filter( 'jetpack_sync_send_data', $original_send_data_cb );
		add_filter( 'jetpack_sync_send_data', $temp_send_data_cb, 10, 6 );
		Sender::get_instance()->do_full_sync();
		remove_filter( 'jetpack_sync_send_data', $temp_send_data_cb );
		add_filter( 'jetpack_sync_send_data', $original_send_data_cb, 10, 6 );

		return array(
			'items'          => $this->items,
			'codec'          => Sender::get_instance()->get_codec()->name(),
			'sent_timestamp' => time(),
			'status'         => Actions::get_sync_status(),
		);
	}

	/**
	 * Checkout items out of the sync queue.
	 *
	 * @param Queue $queue         Sync Queue.
	 * @param int   $number_of_items Number of items to checkout.
	 *
	 * @return WP_Error
	 */
	protected function get_buffer( $queue, $number_of_items ) {
		$start        = time();
		$max_duration = 5; // this will try to get the buffer.

		$buffer   = $queue->checkout( $number_of_items );
		$duration = time() - $start;

		while ( is_wp_error( $buffer ) && $duration < $max_duration ) {
			sleep( 2 );
			$duration = time() - $start;
			$buffer   = $queue->checkout( $number_of_items );
		}

		if ( false === $buffer ) {
			return new WP_Error( 'queue_size', 'The queue is empty and there is nothing to send', 400 );
		}

		return $buffer;
	}

}
