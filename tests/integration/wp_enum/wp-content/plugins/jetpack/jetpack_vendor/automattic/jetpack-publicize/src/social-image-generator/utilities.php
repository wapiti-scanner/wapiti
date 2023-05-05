<?php
/**
 * Utilities.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize\Social_Image_Generator;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Publicize\REST_Controller;
use Automattic\Jetpack\Redirect;

/**
 * Given a post ID, returns the image URL for the generated image.
 *
 * @param int $post_id Post ID to get the URL for.
 * @return string
 */
function get_image_url( $post_id ) {
	$post_settings = new Post_Settings( $post_id );
	$token         = $post_settings->get_token();

	if ( ! $post_settings->is_enabled() || empty( $token ) ) {
		return '';
	}

	return add_query_arg(
		array( 'query' => rawurlencode( 't=' . $token ) ),
		Redirect::get_url( 'sigenerate', array( 'site' => null ) )
	);
}

/**
 * Get the parameters for the token body.
 *
 * @param string $text Text to use in the generated image.
 * @param string $image_url Image to use in the generated image.
 * @param string $template Template to use in the generated image.
 * @return array
 */
function get_token_body( $text, $image_url, $template ) {
	return array(
		'text'      => $text,
		'image_url' => $image_url,
		'template'  => $template,
	);
}

/**
 * Fetch a token from the WPCOM endpoint.
 *
 * @param string $text      The text that will be displayed on the generated image.
 * @param string $image_url The background image URL to be used in the generated image.
 * @param string $template  The template slug to use for generating the image.
 * @return string|WP_Error  The generated token or a WP_Error object if there's been a problem.
 */
function fetch_token( $text, $image_url, $template ) {
	$body            = get_token_body( $text, $image_url, $template );
	$rest_controller = new REST_Controller();
	$response        = Client::wpcom_json_api_request_as_blog(
		sprintf( 'sites/%d/jetpack-social/generate-image-token', absint( \Jetpack_Options::get_option( 'id' ) ) ),
		'2',
		array(
			'headers' => array( 'content-type' => 'application/json' ),
			'method'  => 'POST',
		),
		wp_json_encode( array_filter( $body ) ),
		'wpcom'
	);
	return $rest_controller->make_proper_response( $response );
}

