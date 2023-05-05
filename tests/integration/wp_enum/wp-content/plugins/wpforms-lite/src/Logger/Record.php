<?php

namespace WPForms\Logger;

/**
 * Class Record.
 *
 * @since 1.6.3
 */
class Record {

	/**
	 * Record ID.
	 *
	 * @since 1.6.3
	 *
	 * @var int
	 */
	private $id;

	/**
	 * Record title.
	 *
	 * @since 1.6.3
	 *
	 * @var string
	 */
	private $title;

	/**
	 * Record message.
	 *
	 * @since 1.6.3
	 *
	 * @var string
	 */
	private $message;

	/**
	 * Array, string, or string separated by commas types.
	 *
	 * @since 1.6.3
	 *
	 * @var array|string
	 */
	private $types;

	/**
	 * Datetime of creating record.
	 *
	 * @since 1.6.3
	 *
	 * @var string
	 */
	private $create_at;

	/**
	 * Record form ID.
	 *
	 * @since 1.6.3
	 *
	 * @var int
	 */
	private $form_id;

	/**
	 * Record entry ID.
	 *
	 * @since 1.6.3
	 *
	 * @var int
	 */
	private $entry_id;

	/**
	 * Record user ID.
	 *
	 * @since 1.6.3
	 *
	 * @var int
	 */
	private $user_id;

	/**
	 * Record constructor.
	 *
	 * @since 1.6.3
	 *
	 * @param int          $id        Record ID.
	 * @param string       $title     Record title.
	 * @param string       $message   Record message.
	 * @param array|string $types     Array, string, or string separated by commas types.
	 * @param string       $create_at Datetime of creating record.
	 * @param int          $form_id   Record form ID.
	 * @param int          $entry_id  Record entry ID.
	 * @param int          $user_id   Record user ID.
	 */
	public function __construct( $id, $title, $message, $types, $create_at, $form_id = 0, $entry_id = 0, $user_id = 0 ) {

		$this->id        = $id;
		$this->title     = $title;
		$this->message   = $message;
		$this->types     = $types;
		$this->create_at = strtotime( $create_at );
		$this->form_id   = $form_id;
		$this->entry_id  = $entry_id;
		$this->user_id   = $user_id;
	}

	/**
	 * Get record ID.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	public function get_id() {

		return $this->id;
	}

	/**
	 * Get record title.
	 *
	 * @since 1.6.3
	 *
	 * @return string
	 */
	public function get_title() {

		return $this->title;
	}

	/**
	 * Get record message.
	 *
	 * @since 1.6.3
	 *
	 * @return string
	 */
	public function get_message() {

		return $this->message;
	}

	/**
	 * Get record types.
	 *
	 * @since 1.6.3
	 *
	 * @param string $view Keys or labels.
	 *
	 * @return array
	 */
	public function get_types( $view = 'key' ) {

		$this->types = is_array( $this->types ) ? $this->types : explode( ',', $this->types );

		if ( $view === 'label' ) {
			return array_intersect_key(
				Log::get_log_types(),
				array_flip( $this->types )
			);
		}

		return $this->types;
	}

	/**
	 * Get date of creating record.
	 *
	 * @since 1.6.3
	 *
	 * @param string $format Date format full|short|default sql format.
	 *
	 * @return string
	 */
	public function get_date( $format = 'short' ) {

		switch ( $format ) {
			case 'short':
				$date = date_i18n(
					get_option( 'date_format' ),
					$this->create_at + ( get_option( 'gmt_offset' ) * 3600 )
				);
				break;

			case 'full':
				$date = date_i18n(
					sprintf( '%s %s', get_option( 'date_format' ), get_option( 'time_format' ) ),
					$this->create_at + ( get_option( 'gmt_offset' ) * 3600 )
				);
				break;

			case 'sql':
				$date = gmdate( 'Y-m-d H:i:s', $this->create_at );
				break;

			case 'sql-local':
				$date = date_i18n(
					'Y-m-d H:i:s',
					$this->create_at + ( get_option( 'gmt_offset' ) * 3600 )
				);
				break;

			default:
				$date = '';
				break;
		}

		return $date;
	}

	/**
	 * Get form ID.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	public function get_form_id() {

		return $this->form_id;
	}

	/**
	 * Get entry ID.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	public function get_entry_id() {

		return $this->entry_id;
	}

	/**
	 * Get user ID.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	public function get_user_id() {

		return $this->user_id;
	}

	/**
	 * Create new record.
	 *
	 * @since 1.6.3
	 *
	 * @param string       $title    Record title.
	 * @param string       $message  Record message.
	 * @param array|string $types    Array, string, or string separated by commas types.
	 * @param int          $form_id  Record form ID.
	 * @param int          $entry_id Record entry ID.
	 * @param int          $user_id  Record user ID.
	 *
	 * @return Record
	 */
	public static function create( $title, $message, $types, $form_id = 0, $entry_id = 0, $user_id = 0 ) {

		return new Record(
			0,
			sanitize_text_field( $title ),
			wp_kses( $message, [ 'pre' => [] ] ),
			$types,
			gmdate( 'Y-m-d H:i:s' ),
			absint( $form_id ),
			absint( $entry_id ),
			absint( $user_id )
		);
	}
}
