<?php
/**
 * Legacy and deprecated Jetpack Tracking class.
 *
 * @package automattic/jetpack-compat
 */

use Automattic\Jetpack\Tracking;

/**
 * Legacy class JetpackTracking
 *
 * @deprecated See Automattic\Jetpack\Tracking
 */
class JetpackTracking {

	/**
	 * Enqueue tracks scripts.
	 *
	 * @deprecated See Automattic\Jetpack\Tracking
	 */
	public static function enqueue_tracks_scripts() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Tracking' );

		$tracking = new Tracking();
		return $tracking->enqueue_tracks_scripts();
	}

	/**
	 * Record user event.
	 *
	 * @deprecated See Automattic\Jetpack\Tracking
	 *
	 * @param mixed $event_type Event type.
	 * @param array $data Event data.
	 * @param mixed $user User who did the event.
	 *
	 * @return bool
	 */
	public static function record_user_event( $event_type, $data = array(), $user = null ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Tracking' );

		$tracking = new Tracking();
		return $tracking->record_user_event( $event_type, $data, $user );
	}

}
