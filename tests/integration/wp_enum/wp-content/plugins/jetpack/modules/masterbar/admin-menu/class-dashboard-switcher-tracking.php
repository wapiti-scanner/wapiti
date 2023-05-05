<?php
/**
 * Quick switcher tracking file.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Terms_Of_Service;
use Automattic\Jetpack\Tracking;
use Jetpack_Plan;

/**
 * Class Dashboard_Switcher_Tracking
 */
class Dashboard_Switcher_Tracking {

	/**
	 * Jetpack Tracking library will prefix the event name with "jetpack_*" automatically.
	 */
	const JETPACK_EVENT_NAME = 'dashboard_quick_switch_link_clicked';

	const WPCOM_EVENT_NAME = 'wpcom_dashboard_quick_switch_link_clicked';
	/**
	 * Jetpack tracking object.
	 *
	 * @var Tracking
	 */
	private $tracking;

	/**
	 * Current site plan.
	 *
	 * @var string
	 */
	private $plan;

	/**
	 * The wpcom_tracks wrapper function.
	 *
	 * @var callable
	 */
	private $wpcom_tracking;

	/**
	 * Dashboard_Switcher_Tracking constructor.
	 *
	 * @param Tracking $tracking       Jetpack tracking object.
	 * @param callable $wpcom_tracking A wrapper over wpcom event record.
	 * @param string   $plan           The current site plan.
	 */
	public function __construct( Tracking $tracking, callable $wpcom_tracking, $plan ) {
		$this->tracking       = $tracking;
		$this->plan           = $plan;
		$this->wpcom_tracking = $wpcom_tracking;
	}

	/**
	 * Create an event for the Quick switcher when the user changes it's preferred view.
	 *
	 * @param string $screen The screen page.
	 * @param string $view   The new preferred view.
	 */
	public function record_switch_event( $screen, $view ) {
		$event_props = array(
			'current_page' => $screen,
			'destination'  => $view,
			'plan'         => $this->plan,
		);

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$event_props['blog_id'] = get_current_blog_id();

			/**
			 * Callable injected in the constructor with the static::wpcom_tracks_record_event() static method.
			 *
			 * @see wpcom_tracks_record_event A static method from this class that executes the actual WPCOM event record.
			 */
			$wpcom_tracking = $this->wpcom_tracking;
			$wpcom_tracking( $event_props );
		} else {
			$this->record_jetpack_event( $event_props );
		}
	}

	/**
	 * Get the current site plan or 'N/A' when we cannot determine site's plan.
	 *
	 * @todo: This method can be reused as a wrapper over WPCOM and Atomic as way to get site's current plan (display name).
	 *
	 * @return string
	 */
	public static function get_plan() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			if ( class_exists( '\WPCOM_Store_API' ) ) {
				// @todo: Maybe introduce a wrapper for this since we are duplicating it from WPCOM_Admin_Menu:253
				$products = \WPCOM_Store_API::get_current_plan( \get_current_blog_id() );
				if ( ! empty( $products['product_slug'] ) ) {
					return $products['product_slug'];
				}
			}

			return 'N/A'; // maybe we should return free or null? At the moment it's safe to return 'N/A' since we use it only for passing it to the event.
		}

		// @todo: Maybe introduce a helper for this since we are duplicating it from Atomic_Admin_Menu:240
		$products = Jetpack_Plan::get();
		if ( ! empty( $products['product_slug'] ) ) {
			return $products['product_slug'];
		}

		return 'N/A'; // maybe we should return free or null? At the moment we use it for passing it to the event.
	}

	/**
	 * Record the event with Jetpack implementation.
	 *
	 * For Atomic sites we mark the Jetpack ToS option temporary as read.
	 *
	 * @todo Remove the jetpack_options_tos_agreed filter for Atomic sites after the Tracking is properly working for AT sites.
	 *
	 * @param array $event_properties The event properties.
	 */
	private function record_jetpack_event( $event_properties ) {
		$woa = ( new Host() )->is_woa_site();
		if ( $woa ) {
			add_filter( 'jetpack_options', array( __CLASS__, 'mark_jetpack_tos_as_read' ), 10, 2 );
		}

		$this->tracking->record_user_event( self::JETPACK_EVENT_NAME, $event_properties );

		if ( $woa ) {
			\remove_filter( 'jetpack_options', array( __CLASS__, 'mark_jetpack_tos_as_read' ) );
		}
	}

	/**
	 * Trigger the WPCOM tracks_record_event.
	 *
	 * @param array $event_props Event props.
	 */
	public static function wpcom_tracks_record_event( $event_props ) {
		require_lib( 'tracks/client' );
		\tracks_record_event( \wp_get_current_user(), self::WPCOM_EVENT_NAME, $event_props );
	}

	/**
	 * Get the tracking product name for the Tracking library.
	 *
	 * The tracking product name is used by the Tracking as a prefix for the event name.
	 *
	 * @return string
	 */
	public static function get_jetpack_tracking_product() {
		return ( new Host() )->is_woa_site() ? 'atomic' : 'jetpack';
	}

	/**
	 * Mark the Jetpack ToS as read for Atomic Sites.
	 *
	 * @param mixed  $option_value The value of the Jetpack option.
	 * @param string $option_name The name of the Jetpack option.
	 *
	 * @return bool
	 */
	public static function mark_jetpack_tos_as_read( $option_value, $option_name ) {
		if ( Terms_Of_Service::OPTION_NAME === $option_name ) {
			return true;
		}

		return $option_value;
	}
}
