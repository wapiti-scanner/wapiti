<?php
/**
 * Device detection for Jetpack.
 *
 * @package automattic/jetpack-device-detection
 */

namespace Automattic\Jetpack;

require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/class-user-agent-info.php';

use Automattic\Jetpack\Device_Detection\User_Agent_Info;
use function Automattic\Jetpack\Device_Detection\wp_unslash;

/**
 * Class Device_Detection
 *
 * Determine if the current User Agent matches the passed $kind.
 */
class Device_Detection {

	/**
	 * Returns information about the current device accessing the page.
	 *
	 * @param string $ua (Optional) User-Agent string.
	 *
	 * @return array Device information.
	 *
	 * array(
	 *  'is_phone'            => (bool) Whether the current device is a mobile phone.
	 *  'is_smartphone'       => (bool) Whether the current device is a smartphone.
	 *  'is_tablet'           => (bool) Whether the current device is a tablet device.
	 *  'is_handheld'         => (bool) Whether the current device is a handheld device.
	 *  'is_desktop'          => (bool) Whether the current device is a laptop / desktop device.
	 *  'platform'            => (string) Detected platform.
	 *  'is_phone_matched_ua' => (string) Matched UA.
	 * );
	 */
	public static function get_info( $ua = '' ) {
		$ua_info = new User_Agent_Info( $ua );

		$info = array(
			'is_phone'            => self::is_mobile( 'any', false, $ua_info ),
			'is_phone_matched_ua' => self::is_mobile( 'any', true, $ua_info ),
			'is_smartphone'       => self::is_mobile( 'smart', false, $ua_info ),
			'is_tablet'           => $ua_info->is_tablet(),
			'platform'            => $ua_info->get_platform(),
		);

		$info['is_handheld'] = $info['is_phone'] || $info['is_tablet'];
		$info['is_desktop']  = ! $info['is_handheld'];

		if ( function_exists( 'apply_filters' ) ) {
			/**
			 * Filter the value of Device_Detection::get_info.
			 *
			 * @since 1.0.0
			 *
			 * @param array           $info    Array of device information.
			 * @param string          $ua      User agent string passed to Device_Detection::get_info.
			 * @param User_Agent_Info $ua_info Instance of Automattic\Jetpack\Device_Detection\User_Agent_Info.
			 */
			$info = apply_filters( 'jetpack_device_detection_get_info', $info, $ua, $ua_info );
		}
		return $info;
	}

	/**
	 * Detects phone devices.
	 *
	 * @param string $ua User-Agent string.
	 *
	 * @return bool
	 */
	public static function is_phone( $ua = '' ) {
		$device_info = self::get_info( $ua );
		return true === $device_info['is_phone'];
	}

	/**
	 * Detects smartphone devices.
	 *
	 * @param string $ua User-Agent string.
	 *
	 * @return bool
	 */
	public static function is_smartphone( $ua = '' ) {
		$device_info = self::get_info( $ua );
		return true === $device_info['is_smartphone'];
	}

	/**
	 * Detects tablet devices.
	 *
	 * @param string $ua User-Agent string.
	 *
	 * @return bool
	 */
	public static function is_tablet( $ua = '' ) {
		$device_info = self::get_info( $ua );
		return true === $device_info['is_tablet'];
	}

	/**
	 * Detects desktop devices.
	 *
	 * @param string $ua User-Agent string.
	 *
	 * @return bool
	 */
	public static function is_desktop( $ua = '' ) {
		$device_info = self::get_info( $ua );
		return true === $device_info['is_desktop'];
	}

	/**
	 * Detects handheld (i.e. phone + tablet) devices.
	 *
	 * @param string $ua User-Agent string.
	 *
	 * @return bool
	 */
	public static function is_handheld( $ua = '' ) {
		$device_info = self::get_info( $ua );
		return true === $device_info['is_handheld'];
	}

	/**
	 * Determine if the current User Agent matches the passed $kind.
	 *
	 * @param string          $kind                 Category of mobile device to check for. Either: any, dumb, smart.
	 * @param bool            $return_matched_agent Boolean indicating if the UA should be returned.
	 * @param User_Agent_Info $ua_info              Boolean indicating if the UA should be returned.
	 *
	 * @return bool|string Boolean indicating if current UA matches $kind. If `$return_matched_agent` is true, returns the UA string.
	 */
	private static function is_mobile( $kind, $return_matched_agent, $ua_info ) {
		$kinds         = array(
			'smart' => false,
			'dumb'  => false,
			'any'   => false,
		);
		$first_run     = true;
		$matched_agent = '';

		// If an invalid kind is passed in, reset it to default.
		if ( ! isset( $kinds[ $kind ] ) ) {
				$kind = 'any';
		}

		if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return false;
		}

		$agent = strtolower( filter_var( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) );
		if ( strpos( $agent, 'ipad' ) ) {
			return false;
		}

		// Remove Samsung Galaxy tablets (SCH-I800) from being mobile devices.
		if ( strpos( $agent, 'sch-i800' ) ) {
			return false;
		}

		if ( $ua_info->is_android_tablet() && false === $ua_info->is_kindle_touch() ) {
			return false;
		}

		if ( $ua_info->is_blackberry_tablet() ) {
			return false;
		}

		if ( $first_run ) {
			$first_run = false;

			// checks for iPhoneTier devices & RichCSS devices.
			if ( $ua_info->isTierIphone() || $ua_info->isTierRichCSS() ) {
				$kinds['smart'] = true;
				$matched_agent  = $ua_info->matched_agent;
			}

			if ( ! $kinds['smart'] ) {
				// if smart, we are not dumb so no need to check.
				$dumb_agents = $ua_info->dumb_agents;

				foreach ( $dumb_agents as $dumb_agent ) {
					if ( false !== strpos( $agent, $dumb_agent ) ) {
						$kinds['dumb'] = true;
						$matched_agent = $dumb_agent;

						break;
					}
				}

				if ( ! $kinds['dumb'] ) {
					if ( isset( $_SERVER['HTTP_X_WAP_PROFILE'] ) ) {
						$kinds['dumb'] = true;
						$matched_agent = 'http_x_wap_profile';
					} elseif ( isset( $_SERVER['HTTP_ACCEPT'] ) && ( preg_match( '/wap\.|\.wap/i', $_SERVER['HTTP_ACCEPT'] ) || false !== strpos( strtolower( $_SERVER['HTTP_ACCEPT'] ), 'application/vnd.wap.xhtml+xml' ) ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- This is doing the validating.
						$kinds['dumb'] = true;
						$matched_agent = 'vnd.wap.xhtml+xml';
					}
				}
			}

			if ( $kinds['dumb'] || $kinds['smart'] ) {
				$kinds['any'] = true;
			}
		}

		$value = $kinds[ $kind ];

		if ( $return_matched_agent ) {
			$value = $matched_agent;
		}
		return $value;
	}
}
