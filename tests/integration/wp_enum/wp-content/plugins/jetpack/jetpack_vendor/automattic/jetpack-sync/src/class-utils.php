<?php
/**
 * Sync utils.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * Class for sync utilities.
 */
class Utils {
	/**
	 * Retrieve the values of sync items.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $items Array of sync items.
	 * @return array Array of sync item values.
	 */
	public static function get_item_values( $items ) {
		return array_map( array( __CLASS__, 'get_item_value' ), $items );
	}

	/**
	 * Retrieve the IDs of sync items.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $items Array of sync items.
	 * @return array Array of sync item IDs.
	 */
	public static function get_item_ids( $items ) {
		return array_map( array( __CLASS__, 'get_item_id' ), $items );
	}

	/**
	 * Get the value of a sync item.
	 *
	 * @access private
	 * @static
	 *
	 * @param array $item Sync item.
	 * @return mixed Sync item value.
	 */
	private static function get_item_value( $item ) {
		return $item->value;
	}

	/**
	 * Get the ID of a sync item.
	 *
	 * @access private
	 * @static
	 *
	 * @param array $item Sync item.
	 * @return int Sync item ID.
	 */
	private static function get_item_id( $item ) {
		return $item->id;
	}
}
