<?php
/**
 * Tus_Date Utils.
 *
 * @package VideoPressUploader
 **/

namespace VideoPressUploader;

// Avoid direct calls to this file.
if ( ! defined( 'ABSPATH' ) ) {
	die();
}

/**
 * Class Tus_Date_Utils
 */
class Tus_Date_Utils {
	/**
	 * Returns a UTC date.
	 *
	 * @param null|int|string $s Thing to turn to date utc.
	 *
	 * @return \DateTimeImmutable
	 * @throws \Exception If the thing provided does not make sense.
	 */
	public static function date_utc( $s = null ) {
		return new \DateTimeImmutable( $s, new \DateTimeZone( 'UTC' ) );
	}

	/**
	 * Adds seconds to a date.
	 *
	 * @param \DateTimeImmutable $date The date.
	 * @param int                $seconds The seconds.
	 *
	 * @return \DateTimeImmutable
	 * @throws \Exception If invalid interval.
	 */
	public static function add_seconds( \DateTimeImmutable $date, $seconds ) {
		return $date->add( new \DateInterval( 'PT' . absint( $seconds ) . 'S' ) );
	}
}
