<?php
/**
 * A class that interacts with WP.com A/B tests.
 *
 * @package automattic/jetpack-abtest
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Connection\Client;

/**
 * This class provides an interface to the WP.com A/B tests.
 */
class Abtest {
	/**
	 * A variable to hold the tests we fetched, and their variations for the current user.
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $tests = array();

	/**
	 * Retrieve the test variation for a provided A/B test.
	 *
	 * @access public
	 *
	 * @param string $test_name Name of the A/B test.
	 * @return mixed|null A/B test variation, or null on failure.
	 */
	public function get_variation( $test_name ) {
		$variation = $this->fetch_variation( $test_name );

		// If there was an error retrieving a variation, conceal the error for the consumer.
		if ( is_wp_error( $variation ) ) {
			return null;
		}

		return $variation;
	}

	/**
	 * Fetch and cache the test variation for a provided A/B test from WP.com.
	 *
	 * @access protected
	 *
	 * @param string $test_name Name of the A/B test.
	 * @return mixed|Automattic\Jetpack\Error A/B test variation, or Automattic\Jetpack\Error on failure.
	 */
	protected function fetch_variation( $test_name ) {
		// Make sure test name exists.
		if ( ! $test_name ) {
			return new Error( 'test_name_not_provided', 'A/B test name has not been provided.' );
		}

		// Make sure test name is a valid one.
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $test_name ) ) {
			return new Error( 'invalid_test_name', 'Invalid A/B test name.' );
		}

		// Return cached test variations.
		if ( isset( $this->tests[ $test_name ] ) ) {
			return $this->tests[ $test_name ];
		}

		// Make the request to the WP.com API.
		$response = $this->request_variation( $test_name );

		// Bail if there was an error or malformed response.
		if ( is_wp_error( $response ) || ! is_array( $response ) || ! isset( $response['body'] ) ) {
			return new Error( 'failed_to_fetch_data', 'Unable to fetch the requested data.' );
		}

		// Decode the results.
		$results = json_decode( $response['body'], true );

		// Bail if there were no results or there is no test variation returned.
		if ( ! is_array( $results ) || empty( $results['variation'] ) ) {
			return new Error( 'unexpected_data_format', 'Data was not returned in the expected format.' );
		}

		// Store the variation in our internal cache.
		$this->tests[ $test_name ] = $results['variation'];

		return $results['variation'];
	}

	/**
	 * Perform the request for a variation of a provided A/B test from WP.com.
	 *
	 * @access protected
	 *
	 * @param string $test_name Name of the A/B test.
	 * @return mixed|Automattic\Jetpack\Error A/B test variation, or Automattic\Jetpack\Error on failure.
	 */
	protected function request_variation( $test_name ) {
		return Client::wpcom_json_api_request_as_blog( sprintf( '/abtest/%s', $test_name ), '2', array(), null, 'wpcom' );
	}
}
