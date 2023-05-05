<?php
/**
 * Sync queue buffer.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * A buffer of items from the queue that can be checked out.
 */
class Queue_Buffer {
	/**
	 * Sync queue buffer ID.
	 *
	 * @access public
	 *
	 * @var int
	 */
	public $id;

	/**
	 * Sync items.
	 *
	 * @access public
	 *
	 * @var array
	 */
	public $items_with_ids;

	/**
	 * Constructor.
	 * Initializes the queue buffer.
	 *
	 * @access public
	 *
	 * @param int   $id             Sync queue buffer ID.
	 * @param array $items_with_ids Items for the buffer to work with.
	 */
	public function __construct( $id, $items_with_ids ) {
		$this->id             = $id;
		$this->items_with_ids = $items_with_ids;
	}

	/**
	 * Retrieve the sync items in the buffer, in an ID => value form.
	 *
	 * @access public
	 *
	 * @return bool|array Sync items in the buffer.
	 */
	public function get_items() {
		return array_combine( $this->get_item_ids(), $this->get_item_values() );
	}

	/**
	 * Retrieve the values of the sync items in the buffer.
	 *
	 * @access public
	 *
	 * @return array Sync items values.
	 */
	public function get_item_values() {
		return Utils::get_item_values( $this->items_with_ids );
	}

	/**
	 * Retrieve the IDs of the sync items in the buffer.
	 *
	 * @access public
	 *
	 * @return array Sync items IDs.
	 */
	public function get_item_ids() {
		return Utils::get_item_ids( $this->items_with_ids );
	}
}
