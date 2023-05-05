<?php
/**
 * Stats WPCOM_Stats
 *
 * @package automattic/jetpack-stats
 */

namespace Automattic\Jetpack\Stats;

use Automattic\Jetpack\Connection\Client;
use Jetpack_Options;
use WP_Error;

/**
 * Stats WPCOM_Stats class.
 *
 * Responsible for fetching Stats related data from WPCOM.
 *
 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/
 *
 * @since 0.1.0
 */
class WPCOM_Stats {
	/**
	 * Transient prefix for storing Stats results from the REST API.
	 *
	 * @var string
	 */
	const STATS_CACHE_TRANSIENT_PREFIX = 'jetpack_restapi_stats_cache_';

	/**
	 * Time, in minutes, to cache stats results from the REST API.
	 *
	 * @var int
	 */
	const STATS_CACHE_EXPIRATION_IN_MINUTES = 5;

	/**
	 * Stats REST API version.
	 *
	 * @var string
	 */
	const STATS_REST_API_VERSION = '1.1';

	/**
	 * The stats resource to fetch results for.
	 *
	 * @var string
	 */
	protected $resource;

	/**
	 * Get site's stats.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/
	 * @param array $args Optional query parameters.
	 * @return array| WP_Error
	 */
	public function get_stats( $args = array() ) {
		$this->resource = '';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's summarized views, visitors, likes and comments.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/summary/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_stats_summary( $args = array() ) {
		$this->resource = 'summary';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's top posts and pages by views.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/top-posts/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_top_posts( $args = array() ) {
		$this->resource = 'top-posts';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get the details of a single video.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/video/%24post_id/
	 * @param int   $post_id The video's ID.
	 * @param array $args    Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_video_details( $post_id, $args = array() ) {
		$this->resource = sprintf( 'video/%d', $post_id );

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's referrers.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/referrers/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_referrers( $args = array() ) {
		$this->resource = 'referrers';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's outbound clicks.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/clicks/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_clicks( $args = array() ) {
		$this->resource = 'clicks';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's views by tags and categories.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/tags/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_tags( $args = array() ) {
		$this->resource = 'tags';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's top authors.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/top-authors/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_top_authors( $args = array() ) {
		$this->resource = 'top-authors';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's top comment authors and most-commented posts.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/comments/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_top_comments( $args = array() ) {
		$this->resource = 'comments';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's video plays.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/video-plays/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_video_plays( $args = array() ) {
		$this->resource = 'video-plays';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's file downloads.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/file-downloads/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_file_downloads( $args = array() ) {
		$this->resource = 'file-downloads';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get a post's views.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/post/%24post_id/
	 * @param int   $post_id The video's ID.
	 * @param array $args    Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_post_views( $post_id, $args = array() ) {
		$this->resource = sprintf( 'post/%d', $post_id );

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's views by country.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/country-views/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_views_by_country( $args = array() ) {

		$this->resource = 'country-views';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's followers.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/followers/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_followers( $args = array() ) {

		$this->resource = 'followers';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's comment followers.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/comment-followers/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_comment_followers( $args = array() ) {

		$this->resource = 'comment-followers';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get site's publicize follower counts.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/publicize/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_publicize_followers( $args = array() ) {

		$this->resource = 'publicize';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get search terms used to find the site.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/search-terms/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_search_terms( $args = array() ) {

		$this->resource = 'search-terms';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get the total number of views for each post.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/views/posts/
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_total_post_views( $args = array() ) {

		$this->resource = 'views/posts';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get the number of visits for the site.
	 *
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_visits( $args = array() ) {

		$this->resource = 'visits';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get streaks for the site.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/streak/
	 *
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_streak( $args = array() ) {

		$this->resource = 'streak';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get the highlights for the site.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/highlights/
	 *
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_highlights( $args = array() ) {

		$this->resource = 'highlights';

		return $this->fetch_stats( $args );
	}

	/**
	 * Get the number of visits for the site.
	 *
	 * @param array $args Optional query parameters.
	 * @return array|WP_Error
	 */
	public function get_insights( $args = array() ) {

		$this->resource = 'insights';

		return $this->fetch_stats( $args );
	}

	/**
	 * Build WPCOM REST API endpoint.
	 *
	 * @return string
	 */
	protected function build_endpoint() {
		$resource = ltrim( $this->resource, '/' );

		return sprintf( '/sites/%d/stats/%s', Jetpack_Options::get_option( 'id' ), $resource );
	}

	/**
	 * Fetches stats data from WPCOM or local Cache. Caches locally for 5 minutes.
	 *
	 * @param array $args Optional query parameters.
	 *
	 * @return array|WP_Error
	 */
	protected function fetch_stats( $args = array() ) {
		$endpoint       = $this->build_endpoint();
		$api_version    = self::STATS_REST_API_VERSION;
		$cache_key      = md5( implode( '|', array( $endpoint, $api_version, wp_json_encode( $args ) ) ) );
		$transient_name = self::STATS_CACHE_TRANSIENT_PREFIX . $cache_key;
		$stats_cache    = get_transient( $transient_name );

		if ( $stats_cache ) {
			$time = key( $stats_cache );
			$data = $stats_cache[ $time ]; // WP_Error or string (JSON encoded object).

			if ( is_wp_error( $data ) ) {
				return $data;
			}

			return array_merge( array( 'cached_at' => $time ), (array) json_decode( $data, true ) );
		}

		$wpcom_stats = $this->fetch_remote_stats( $endpoint, $args );

		// To reduce size in storage: store with time as key, store JSON encoded data.
		$cached_value = is_wp_error( $wpcom_stats ) ? $wpcom_stats : wp_json_encode( $wpcom_stats );
		$expiration   = self::STATS_CACHE_EXPIRATION_IN_MINUTES * MINUTE_IN_SECONDS;
		set_transient( $transient_name, array( time() => $cached_value ), $expiration );

		return $wpcom_stats;
	}

	/**
	 * Fetches stats data from WPCOM.
	 *
	 * @link https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/stats/
	 * @param string $endpoint The stats endpoint.
	 * @param array  $args The query arguments.
	 * @return array|WP_Error.
	 */
	protected function fetch_remote_stats( $endpoint, $args ) {
		if ( is_array( $args ) && ! empty( $args ) ) {
			$endpoint .= '?' . http_build_query( $args );
		}
		$response      = Client::wpcom_json_api_request_as_blog( $endpoint, self::STATS_REST_API_VERSION );
		$response_code = wp_remote_retrieve_response_code( $response );
		$response_body = wp_remote_retrieve_body( $response );

		if ( is_wp_error( $response ) || 200 !== $response_code || empty( $response_body ) ) {
			return is_wp_error( $response ) ? $response : new WP_Error( 'stats_error', 'Failed to fetch Stats from WPCOM' );
		}

		return json_decode( $response_body, true );
	}
}
