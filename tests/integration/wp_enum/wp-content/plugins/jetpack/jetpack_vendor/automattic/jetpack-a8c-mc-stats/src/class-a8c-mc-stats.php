<?php
/**
 * Jetpack MC Stats package.
 *
 * @package  automattic/jetpack-mc-stats
 */

namespace Automattic\Jetpack;

/**
 * Class MC Stats, used to record stats using https://pixel.wp.com/g.gif
 */
class A8c_Mc_Stats {

	/**
	 * Holds the stats to be processed
	 *
	 * @var array
	 */
	private $stats = array();

	/**
	 * Indicates whether to use the transparent pixel (b.gif) instead of the regular smiley (g.gif)
	 *
	 * @var boolean
	 */
	public $use_transparent_pixel = true;

	/**
	 * Class Constructor
	 *
	 * @param boolean $use_transparent_pixel Use the transparent pixel instead of the smiley.
	 */
	public function __construct( $use_transparent_pixel = true ) {
		$this->use_transparent_pixel = $use_transparent_pixel;
	}

	/**
	 * Store a stat for later output.
	 *
	 * @param string $group The stat group.
	 * @param string $name The stat name to bump.
	 *
	 * @return boolean true if stat successfully added
	 */
	public function add( $group, $name ) {

		if ( ! \is_string( $group ) || ! \is_string( $name ) ) {
			return false;
		}

		if ( ! isset( $this->stats[ $group ] ) ) {
			$this->stats[ $group ] = array();
		}

		if ( \in_array( $name, $this->stats[ $group ], true ) ) {
			return false;
		}

		$this->stats[ $group ][] = $name;

		return true;
	}

	/**
	 * Gets current stats stored to be processed
	 *
	 * @return array $stats
	 */
	public function get_current_stats() {
		return $this->stats;
	}

	/**
	 * Return the stats from a group in an array ready to be added as parameters in a query string
	 *
	 * @param string $group_name The name of the group to retrieve.
	 * @return array Array with one item, where the key is the prefixed group and the value are all stats concatenated with a comma. If group not found, an empty array will be returned
	 */
	public function get_group_query_args( $group_name ) {
		$stats = $this->get_current_stats();
		if ( isset( $stats[ $group_name ] ) && ! empty( $stats[ $group_name ] ) ) {
			return array( "x_jetpack-{$group_name}" => implode( ',', $stats[ $group_name ] ) );
		}
		return array();
	}

	/**
	 * Gets a list of trac URLs for every stored URL
	 *
	 * @return array An array of URLs
	 */
	public function get_stats_urls() {

		$urls = array();

		foreach ( $this->get_current_stats() as $group => $stat ) {
			$group_query_string = $this->get_group_query_args( $group );
			$urls[]             = $this->build_stats_url( $group_query_string );
		}

		return $urls;
	}

	/**
	 * Outputs the tracking pixels for the current stats and empty the stored stats from the object
	 *
	 * @return void
	 */
	public function do_stats() {
		$urls = $this->get_stats_urls();
		foreach ( $urls as $url ) {
			echo '<img src="' . esc_url( $url ) . '" width="1" height="1" style="display:none;" />';
		}
		$this->stats = array();
	}

	/**
	 * Pings the stats server for the current stats and empty the stored stats from the object
	 *
	 * @return void
	 */
	public function do_server_side_stats() {
		$urls = $this->get_stats_urls();
		foreach ( $urls as $url ) {
			$this->do_server_side_stat( $url );
		}
		$this->stats = array();
	}

	/**
	 * Runs stats code for a one-off, server-side.
	 *
	 * @param string $url string The URL to be pinged. Should include `x_jetpack-{$group}={$stats}` or whatever we want to store.
	 *
	 * @return bool If it worked.
	 */
	public function do_server_side_stat( $url ) {
		$response = wp_remote_get( esc_url_raw( $url ) );
		if ( is_wp_error( $response ) ) {
			return false;
		}

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Builds the stats url.
	 *
	 * @param array $args array|string The arguments to append to the URL.
	 *
	 * @return string The URL to be pinged.
	 */
	public function build_stats_url( $args ) {
		$defaults = array(
			'v'    => 'wpcom2',
			'rand' => md5( wp_rand( 0, 999 ) . time() ),
		);
		$args     = wp_parse_args( $args, $defaults );
		$gifname  = true === $this->use_transparent_pixel ? 'b.gif' : 'g.gif';

		/**
		 * Filter the URL used as the Stats tracking pixel.
		 *
		 * @since-jetpack 2.3.2
		 * @since 1.0.0
		 *
		 * @param string $url Base URL used as the Stats tracking pixel.
		 */
		$base_url = apply_filters(
			'jetpack_stats_base_url',
			'https://pixel.wp.com/' . $gifname
		);
		$url      = add_query_arg( $args, $base_url );
		return $url;
	}

}
