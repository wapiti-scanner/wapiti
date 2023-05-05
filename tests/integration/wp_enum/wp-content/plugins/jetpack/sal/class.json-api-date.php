<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * WPCOM_JSON_API_Date class.
 *
 * @package automattic/jetpack
 */
/**
 * Base class for WPCOM_JSON_API_Date.
 */
class WPCOM_JSON_API_Date {
	/**
	 * Returns ISO 8601 formatted datetime: 2011-12-08T01:15:36-08:00
	 *
	 * @param string $date_gmt GMT datetime string.
	 * @param string $date Optional.  Used to calculate the offset from GMT.
	 *
	 * @return string
	 */
	public static function format_date( $date_gmt, $date = null ) {
		$timestamp_gmt = strtotime( "$date_gmt+0000" );

		if ( null === $date ) {
			$timestamp = $timestamp_gmt;
			$west      = 0;
			$minutes   = 0;
			$hours     = 0;
		} else {
			$date_time = date_create( "$date+0000" );
			if ( $date_time ) {
				$timestamp = date_format( $date_time, 'U' );
			} else {
				$timestamp = 0;
			}

			// "0000-00-00 00:00:00" == -62169984000
			if ( -62169984000 === $timestamp_gmt ) {
				// WordPress sets post_date=now, post_date_gmt="0000-00-00 00:00:00" for all drafts
				// WordPress sets post_modified=now, post_modified_gmt="0000-00-00 00:00:00" for new drafts.

				// Try to guess the correct offset from the blog's options.
				$timezone_string = get_option( 'timezone_string' );

				if ( $timezone_string && $date_time ) {
					$timezone = timezone_open( $timezone_string );
					if ( $timezone ) {
						$offset = $timezone->getOffset( $date_time );
					}
				} else {
					$offset = 3600 * get_option( 'gmt_offset' );
				}
			} else {
				$offset = $timestamp - $timestamp_gmt;
			}

			$west    = $offset < 0;
			$offset  = abs( $offset );
			$hours   = (int) floor( $offset / 3600 );
			$offset -= $hours * 3600;
			$minutes = (int) floor( $offset / 60 );
		}

		return (string) gmdate( 'Y-m-d\\TH:i:s', $timestamp ) . sprintf( '%s%02d:%02d', $west ? '-' : '+', $hours, $minutes );
	}

	/**
	 * Returns ISO 8601 formatted duration interval: P0DT1H10M0S
	 *
	 * @param string $time Duration in minutes or hours.
	 *
	 * @return null|string
	 */
	public static function format_duration( $time ) {
		$timestamp = strtotime( $time, 0 );

		// Bail early if we don't recognize a date.
		if ( empty( $timestamp ) ) {
			return;
		}

		$days      = floor( $timestamp / 86400 );
		$timestamp = $timestamp % 86400;

		$hours     = floor( $timestamp / 3600 );
		$timestamp = $timestamp % 3600;

		$minutes   = floor( $timestamp / 60 );
		$timestamp = $timestamp % 60;

		return (string) sprintf(
			'P%dDT%dH%dM%dS',
			$days,
			$hours,
			$minutes,
			$timestamp
		);
	}
}
