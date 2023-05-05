<?php

namespace WPForms\Logger;

use Iterator;
use Countable;

/**
 * Class Records.
 *
 * @since 1.6.3
 */
class Records implements Countable, Iterator {

	/**
	 * Iterator position.
	 *
	 * @since 1.6.3
	 *
	 * @var int
	 */
	private $iterator_position = 0;

	/**
	 * List of log records.
	 *
	 * @since 1.6.3
	 *
	 * @var array
	 */
	private $list = [];

	/**
	 * Return the current element.
	 *
	 * @since 1.6.3
	 *
	 * @return \WPForms\Logger\Record|null Return null when no items in collection.
	 */
	#[\ReturnTypeWillChange]
	public function current() {

		return $this->valid() ? $this->list[ $this->iterator_position ] : null;
	}

	/**
	 * Move forward to next element.
	 *
	 * @since 1.6.3
	 */
	#[\ReturnTypeWillChange]
	public function next() {

		++ $this->iterator_position;
	}

	/**
	 * Return the key of the current element.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	#[\ReturnTypeWillChange]
	public function key() {

		return $this->iterator_position;
	}

	/**
	 * Checks if current position is valid.
	 *
	 * @since 1.6.3
	 *
	 * @return bool
	 */
	#[\ReturnTypeWillChange]
	public function valid() {

		return isset( $this->list[ $this->iterator_position ] );
	}

	/**
	 * Rewind the Iterator to the first element.
	 *
	 * @since 1.6.3
	 */
	#[\ReturnTypeWillChange]
	public function rewind() {

		$this->iterator_position = 0;
	}

	/**
	 * Count number of Record in a Queue.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	#[\ReturnTypeWillChange]
	public function count() {

		return count( $this->list );
	}

	/**
	 * Push record to list.
	 *
	 * @since 1.6.3
	 *
	 * @param \WPForms\Logger\Record $record Record.
	 */
	#[\ReturnTypeWillChange]
	public function push( $record ) {

		if ( ! is_a( $record, '\WPForms\Logger\Record' ) ) {
			return;
		}
		$this->list[] = $record;
	}

	/**
	 * Clear collection.
	 *
	 * @since 1.6.3
	 */
	#[\ReturnTypeWillChange]
	public function clear() {

		$this->list              = [];
		$this->iterator_position = 0;
	}
}
