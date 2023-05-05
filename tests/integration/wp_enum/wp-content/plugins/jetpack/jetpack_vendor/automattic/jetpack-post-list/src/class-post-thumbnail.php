<?php
/**
 * This file contains the Post_Thumbnail class used for finding a suitable thumbnail for a post.
 *
 * @package automattic/jetpack-post-list
 */

namespace Automattic\Jetpack\Post_List;

/**
 * The Post_Thumbnail class contains methods to find and return a suitable thumbnail for a post.
 */
class Post_Thumbnail {
	/**
	 * Returns the featured image thumbnail or if no featured image is set, return the first image in the post. If
	 * neither exists returns the image array with null values.
	 *
	 * @param object $post The current post.
	 * @return array|null The thumbnail image id and URLs
	 */
	public static function get_post_thumbnail( $post ) {
		$image_id    = null;
		$image_url   = null;
		$image_alt   = null;
		$image_thumb = false;

		$post_id = $post->ID;

		// If a featured image exists for the post, use that thumbnail.
		if ( has_post_thumbnail( $post_id ) ) {
			$image_id    = get_post_thumbnail_id( $post_id );
			$image_url   = get_the_post_thumbnail_url( $post_id );
			$image_thumb = get_the_post_thumbnail_url( $post_id, array( 50, 50 ) );
			$image_alt   = get_post_meta( $image_id, '_wp_attachment_image_alt', true );
		} else {
			// If a featured image does not exist look for the first "media library" hosted image on the post.
			$attachment_id = self::get_first_image_id_from_post_content( $post->post_content );

			if ( null !== $attachment_id ) {
				$image_id    = $attachment_id;
				$image_url   = wp_get_attachment_image_url( $attachment_id, 'full-size' );
				$image_thumb = wp_get_attachment_image_url( $attachment_id, array( 50, 50 ) );
				$image_alt   = get_post_meta( $attachment_id, '_wp_attachment_image_alt', true );
			}
		}

		// If no thumbnail is found return null.
		if ( false === $image_thumb ) {
			return null;
		}

		// Escape values just in case.
		return array(
			'id'    => esc_attr( $image_id ),
			'url'   => esc_url( $image_url ),
			'thumb' => esc_url( $image_thumb ),
			'alt'   => esc_attr( $image_alt ),
		);
	}

	/**
	 * Looks for the first image in the post content containing a class value of 'wp-image-{$attachment_id}' and
	 * returns the $attachment_id from that class value.
	 *
	 * @param string $post_content The current post's HTML content.
	 * @return int The image attachment id.
	 */
	public static function get_first_image_id_from_post_content( $post_content ) {
		// If $post_content does not contain a value of substance, return null right away and avoid trying to parse it.
		if ( empty( $post_content ) ) {
			return null;
		}

		$attachment_id = null;
		$dom           = new \DOMDocument();

		// libxml_use_internal_errors(true) silences PHP warnings and errors from malformed HTML in loadHTML().
		// you can consult libxml_get_last_error() or libxml_get_errors() to check for errors if needed.
		libxml_use_internal_errors( true );
		$dom->loadHTML( $post_content );

		// Media library images have a class attribute value containing 'wp-image-{$attachment_id}'.
		// Use DomXPath to parse the post content and get the first img tag containing 'wp-image-' as a class value.
		$class_name = 'wp-image-';
		$dom_x_path = new \DomXPath( $dom );
		$nodes      = $dom_x_path->query( "//img[contains(@class, '$class_name')]/@class" );

		if ( $nodes->length > 0 ) {
			// Get the class attribute value of the 1st image node (aka index 0).
			$class_value = $nodes[0]->value;

			// Ignore all class attribute values except 'wp-image{$attachment_id}'.
			// Regex english translation: Look for a word \b, that does not start or end with a hyphen (?!-), that
			// starts with 'wp-image-', and ends with a number of any length \d+.
			$class_name_found = preg_match( '/\b(?!-)wp-image-\d+(?!-)\b/', $class_value, $class_value );

			if ( $class_name_found ) {
				// Get the $attachment_id from the end of the class name value.
				$attachment_id = str_replace( $class_name, '', $class_value[0] );

				// If the ID we found is numeric, cast it as an int. Else, make it null.
				if ( is_numeric( $attachment_id ) ) {
					$attachment_id = (int) $attachment_id;
				} else {
					$attachment_id = null;
				}
			}
		}

		return $attachment_id;
	}
}
