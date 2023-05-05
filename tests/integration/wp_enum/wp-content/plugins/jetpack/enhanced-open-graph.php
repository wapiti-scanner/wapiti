<?php
/**
 * Enhanced Open Graph for Jetpack.
 *
 * @package automattic/jetpack
 */

if ( ! class_exists( 'Jetpack_Media_Summary' ) ) {
	require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media-summary.php';
}

/**
 * Better OG Image Tags for Image Post Formats
 *
 * @param array $tags Array of Open Graph tags.
 */
function enhanced_og_image( $tags ) {
	if ( ! is_singular() || post_password_required() ) {
		return $tags;
	}

	global $post;

	// Bail if we do not have info about the post.
	if ( ! $post instanceof WP_Post ) {
		return $tags;
	}

	// Always favor featured images.
	if ( enhanced_og_has_featured_image( $post->ID ) ) {
		return $tags;
	}

	$summary = Jetpack_Media_Summary::get( $post->ID );

	if ( 'image' !== $summary['type'] ) {
		return $tags;
	}

	$tags['og:image']            = $summary['image'];
	$tags['og:image:secure_url'] = $summary['secure']['image'];

	return $tags;
}
add_filter( 'jetpack_open_graph_tags', 'enhanced_og_image' );

/**
 * Better OG Image Tags for Gallery Post Formats
 *
 * @param array $tags Array of Open Graph tags.
 */
function enhanced_og_gallery( $tags ) {
	if ( ! is_singular() || post_password_required() ) {
		return $tags;
	}

	global $post;

	// Bail if we do not have info about the post.
	if ( ! $post instanceof WP_Post ) {
		return $tags;
	}

	// Always favor featured images.
	if ( enhanced_og_has_featured_image( $post->ID ) ) {
		return $tags;
	}

	$summary = Jetpack_Media_Summary::get( $post->ID );

	if ( 'gallery' !== $summary['type'] ) {
		return $tags;
	}

	if ( ! isset( $summary['images'] ) || ! is_array( $summary['images'] ) || empty( $summary['images'] ) ) {
		return $tags;
	}

	$images  = array();
	$secures = array();

	foreach ( $summary['images'] as $i => $image ) {
		$images[]  = $image['url'];
		$secures[] = $summary['secure']['images'][ $i ]['url'];
	}

	$tags['og:image']            = $images;
	$tags['og:image:secure_url'] = $secures;

	return $tags;
}
add_filter( 'jetpack_open_graph_tags', 'enhanced_og_gallery' );

/**
 * Allows VideoPress, YouTube, and Vimeo videos to play inline on Facebook
 *
 * @param array $tags Array of Open Graph tags.
 */
function enhanced_og_video( $tags ) {
	if ( ! is_singular() || post_password_required() ) {
		return $tags;
	}

	global $post;

	// Bail if we do not have info about the post.
	if ( ! $post instanceof WP_Post ) {
		return $tags;
	}

	// Always favor featured images.
	if ( enhanced_og_has_featured_image( $post->ID ) ) {
		return $tags;
	}

	$summary = Jetpack_Media_Summary::get( $post->ID );

	if ( 'video' !== $summary['type'] ) {
		if ( $summary['count']['video'] > 0 && $summary['count']['image'] < 1 ) {
			$tags['og:image']            = $summary['image'];
			$tags['og:image:secure_url'] = $summary['secure']['image'];
		}
		return $tags;
	}

	$tags['og:image']            = $summary['image'];
	$tags['og:image:secure_url'] = $summary['secure']['image'];

	// This should be html by default for youtube/vimeo, since we're linking to HTML pages.
	$tags['og:video:type'] = isset( $summary['video_type'] ) ? $summary['video_type'] : 'text/html';

	$video_url        = $summary['video'];
	$secure_video_url = $summary['secure']['video'];

	if ( preg_match( '/((youtube|vimeo)\.com|youtu.be)/', $video_url ) ) {
		if ( strstr( $video_url, 'youtube' ) ) {
			$id               = jetpack_get_youtube_id( $video_url );
			$video_url        = 'http://www.youtube.com/embed/' . $id;
			$secure_video_url = 'https://www.youtube.com/embed/' . $id;
		} elseif ( strstr( $video_url, 'vimeo' ) ) {
			preg_match( '|vimeo\.com/(\d+)/?$|i', $video_url, $match );
			$id               = (int) $match[1];
			$video_url        = 'http://vimeo.com/moogaloop.swf?clip_id=' . $id;
			$secure_video_url = 'https://vimeo.com/moogaloop.swf?clip_id=' . $id;
		}
	}

	$tags['og:video']            = $video_url;
	$tags['og:video:secure_url'] = $secure_video_url;

	if ( empty( $post->post_title ) ) {
		/* translators: %s is the name of the site */
		$tags['og:title'] = sprintf( __( 'Video on %s', 'jetpack' ), get_option( 'blogname' ) );
	}

	return $tags;
}
add_filter( 'jetpack_open_graph_tags', 'enhanced_og_video' );

/**
 * Check if a post has a suitable featured image.
 *
 * @param int $post_id The post ID to check.
 * @return bool True if the post has a suitable featured image, false otherwise.
 */
function enhanced_og_has_featured_image( $post_id ) {
	return ! empty( Jetpack_PostImages::from_thumbnail( $post_id ) );
}
