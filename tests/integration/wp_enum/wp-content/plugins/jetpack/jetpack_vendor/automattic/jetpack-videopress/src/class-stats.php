<?php
/**
 * Provides data stats about videos inside VideoPress
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Client;
use WP_Error;

/**
 * Provides data stats about videos inside VideoPress
 */
class Stats {
	/**
	 * Hit WPCOM video-plays stats endpoint.
	 *
	 * @param array $args Request args.
	 * @return array|WP_Error WP HTTP response on success
	 */
	public static function fetch_video_plays( $args = array() ) {
		$blog_id = VideoPressToken::blog_id();

		$endpoint = sprintf(
			'sites/%d/stats/video-plays?check_stats_module=false',
			$blog_id
		);

		if ( is_array( $args ) && ! empty( $args ) ) {
			$endpoint .= '&' . http_build_query( $args );
		}

		$result = Client::wpcom_json_api_request_as_blog( $endpoint );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$response      = $result['http_response'];
		$response_code = $response->get_status();
		$response_body = json_decode( $response->get_data(), true );

		if ( 200 !== $response_code ) {
			return new WP_Error(
				'videopress_stats_error',
				$response_body
			);
		}

		return array(
			'code' => $response_code,
			'data' => $response_body,
		);
	}

	/**
	 * Returns the counter of today's plays for all videos.
	 *
	 * @return int|WP_Error the total of plays for today, or WP_Error on failure.
	 */
	public static function get_today_plays() {
		$response = self::fetch_video_plays();

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data = $response['data'];

		if ( ! $data || ! isset( $data['days'] ) || count( $data['days'] ) === 0 ) {
			return new WP_Error(
				'videopress_stats_error',
				__( 'Could not find any stats from the service', 'jetpack-videopress-pkg' )
			);
		}

		/*
		 * The only result here is today's stats
		 */
		$today_stats = array_pop( $data['days'] );

		return $today_stats['total_plays'];
	}

	/**
	 * Returns the featured stats for VideoPress.
	 *
	 * @return array|WP_Error a list of stats, or WP_Error on failure.
	 */
	public static function get_featured_stats() {
		$response = self::fetch_video_plays(
			array(
				'period'         => 'day',
				'num'            => 14,
				'complete_stats' => true,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data = $response['data'];

		if ( ! $data ) {
			return new WP_Error(
				'videopress_stats_error',
				__( 'Could not find any stats from the service', 'jetpack-videopress-pkg' )
			);
		}

		// Get only the list of dates
		$dates = $data['days'];

		// Organize the data into the planned stats
		return self::prepare_featured_stats( $dates );
	}

	/**
	 * Prepares the featured stats for VideoPress.
	 *
	 * @param array $dates The list of dates returned by the API.
	 * @return array a list of stats.
	 */
	public static function prepare_featured_stats( $dates ) {
		/**
		 * Ensure the sorting of the dates, recent ones first.
		 * This way, the first 7 positions are from the last 7 days,
		 * and the next 7 positions are from the 7 days before it.
		 */
		krsort( $dates );

		// template for the response
		$featured_stats = array(
			'label' => __( 'last 7 days', 'jetpack-videopress-pkg' ),
			'data'  => array(
				'views'       => array(
					'current'  => 0,
					'previous' => 0,
				),
				'impressions' => array(
					'current'  => 0,
					'previous' => 0,
				),
				'watch_time'  => array(
					'current'  => 0,
					'previous' => 0,
				),
			),
		);

		// Go through the dates to compute the stats
		$counter = 0;
		foreach ( $dates as $date_info ) {
			$date_totals = $date_info['total'];

			if ( $counter < 7 ) {

				// the first 7 elements are for the current period
				$featured_stats['data']['views']['current']       += $date_totals['views'];
				$featured_stats['data']['impressions']['current'] += $date_totals['impressions'];
				$featured_stats['data']['watch_time']['current']  += $date_totals['watch_time'];

			} else {

				// the next 7 elements are for the previous period
				$featured_stats['data']['views']['previous']       += $date_totals['views'];
				$featured_stats['data']['impressions']['previous'] += $date_totals['impressions'];
				$featured_stats['data']['watch_time']['previous']  += $date_totals['watch_time'];

			}

			++$counter;
		}

		return $featured_stats;
	}
}
