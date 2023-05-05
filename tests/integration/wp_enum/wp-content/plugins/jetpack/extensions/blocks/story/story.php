<?php
/**
 * Story Block.
 *
 * @since 8.6.1
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Story;

use Automattic\Jetpack\Blocks;
use Jetpack;
use Jetpack_Gutenberg;
use Jetpack_PostImages;

const FEATURE_NAME = 'story';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

const EMBED_SIZE        = array( 360, 640 ); // twice as many pixels for retina displays.
const CROP_UP_TO        = 0.2;
const MAX_BULLETS       = 7;
const IMAGE_BREAKPOINTS = '(max-width: 460px) 576w, (max-width: 614px) 768w, 120vw'; // 120vw to match the 20% CROP_UP_TO ratio

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array( 'render_callback' => __NAMESPACE__ . '\render_block' )
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Compare 2 urls and return true if they likely correspond to the same resource.
 * Ignore scheme, ports, query params and hashes and only compare hostname and pathname.
 *
 * @param string $url1  - First url used in comparison.
 * @param string $url2  - Second url used in comparison.
 *
 * @returns boolean
 */
function is_same_resource( $url1, $url2 ) {
	$url1_parsed = wp_parse_url( $url1 );
	$url2_parsed = wp_parse_url( $url2 );
	return isset( $url1_parsed['host'] ) &&
		isset( $url2_parsed['host'] ) &&
		isset( $url1_parsed['path'] ) &&
		isset( $url2_parsed['path'] ) &&
		$url1_parsed['host'] === $url2_parsed['host'] &&
		$url1_parsed['path'] === $url2_parsed['path'];
}

/**
 * Enrich media files retrieved from the story block attributes
 * with extra information we can retrieve from the media library.
 *
 * @param array $media_files  - List of media, each as an array containing the media attributes.
 *
 * @returns array $media_files
 */
function enrich_media_files( $media_files ) {
	return array_filter(
		array_map(
			function ( $media_file ) {
				if ( 'image' === $media_file['type'] ) {
					return enrich_image_meta( $media_file );
				}
				// VideoPress videos can sometimes have type 'file', and mime 'video/videopress' or 'video/mp4'.
				// Let's fix `type` for those.
				if ( 'file' === $media_file['type'] && 'video' === substr( $media_file['mime'], 0, 5 ) ) {
					$media_file['type'] = 'video';
				}
				if ( 'video' !== $media_file['type'] ) { // we only support images and videos at this point.
					return null;
				}
				return enrich_video_meta( $media_file );
			},
			$media_files
		)
	);
}

/**
 * Enrich image information with extra data we can retrieve from the media library.
 * Add missing `width`, `height`, `srcset`, `sizes`, `title`, `alt` and `caption` properties to the image.
 *
 * @param array $media_file  - An array containing the media attributes for a specific image.
 *
 * @returns array $media_file_enriched
 */
function enrich_image_meta( $media_file ) {
	$attachment_id = isset( $media_file['id'] ) ? $media_file['id'] : null;
	$image         = wp_get_attachment_image_src( $attachment_id, 'full', false );
	if ( ! $image ) {
		return $media_file;
	}
	list( $src, $width, $height ) = $image;
	// Bail if url stored in block attributes is different than the media library one for that id.
	if ( isset( $media_file['url'] ) && ! is_same_resource( $media_file['url'], $src ) ) {
		return $media_file;
	}
	$image_meta = wp_get_attachment_metadata( $attachment_id );
	if ( ! is_array( $image_meta ) ) {
		return $media_file;
	}
	$size_array = array( absint( $width ), absint( $height ) );
	return array_merge(
		$media_file,
		array(
			'width'   => absint( $width ),
			'height'  => absint( $height ),
			'srcset'  => wp_calculate_image_srcset( $size_array, $src, $image_meta, $attachment_id ),
			'sizes'   => IMAGE_BREAKPOINTS,
			'title'   => get_the_title( $attachment_id ),
			'alt'     => get_post_meta( $attachment_id, '_wp_attachment_image_alt', true ),
			'caption' => wp_get_attachment_caption( $attachment_id ),
		)
	);
}

/**
 * Enrich video information with extra data we can retrieve from the media library.
 * Add missing `width`, `height`, `alt`, `url`, `title`, `caption` and `poster` properties to the image.
 *
 * @param array $media_file  - An array containing the media attributes for a specific video.
 *
 * @returns array $media_file_enriched
 */
function enrich_video_meta( $media_file ) {
	$attachment_id = isset( $media_file['id'] ) ? $media_file['id'] : null;
	$video_meta    = wp_get_attachment_metadata( $attachment_id );
	if ( ! $video_meta ) {
		return $media_file;
	}

	$video_url = ! empty( $video_meta['original']['url'] ) ? $video_meta['original']['url'] : wp_get_attachment_url( $attachment_id );

	// Set the poster attribute for the video tag if a poster image is available.
	$poster_url = null;
	if ( ! empty( $video_meta['videopress']['poster'] ) ) {
		$poster_url = $video_meta['videopress']['poster'];
	} elseif ( ! empty( $video_meta['thumb'] ) ) {
		$poster_url = str_replace( wp_basename( $video_url ), $video_meta['thumb'], $video_url );
	}

	if ( $poster_url ) {
		// Use the global content width for thumbnail resize so we match the `w=` query parameter
		// that jetpack is going to add when "Enable site accelerator" is enabled for images.
		$content_width = (int) Jetpack::get_content_width();
		$new_width     = $content_width > 0 ? $content_width : EMBED_SIZE[0];
		$poster_url    = add_query_arg( 'w', $new_width, $poster_url );
	}

	return array_merge(
		$media_file,
		array(
			'width'   => absint( ! empty( $video_meta['width'] ) ? $video_meta['width'] : $media_file['width'] ),
			'height'  => absint( ! empty( $video_meta['height'] ) ? $video_meta['height'] : $media_file['height'] ),
			'alt'     => ! empty( $video_meta['videopress']['description'] ) ? $video_meta['videopress']['description'] : $media_file['alt'],
			'url'     => $video_url,
			'title'   => get_the_title( $attachment_id ),
			'caption' => wp_get_attachment_caption( $attachment_id ),
			'poster'  => $poster_url,
		)
	);
}

/**
 * Render an image inside a slide
 *
 * @param array $media  - Image information.
 *
 * @returns string
 */
function render_image( $media ) {
	if ( empty( $media['id'] ) || empty( $media['url'] ) ) {
		return __( 'Error retrieving media', 'jetpack' );
	}
	$image = wp_get_attachment_image_src( $media['id'], 'full', false );
	if ( $image ) {
		list( $src, $width, $height ) = $image;
	}

	// if image does not match.
	if ( ! $image || isset( $media['url'] ) && ! is_same_resource( $media['url'], $src ) ) {
		$width  = isset( $media['width'] ) ? $media['width'] : null;
		$height = isset( $media['height'] ) ? $media['height'] : null;
		$title  = isset( $media['title'] ) ? $media['title'] : '';
		$alt    = isset( $media['alt'] ) ? $media['alt'] : '';
		return sprintf(
			'<img
				title="%1$s"
				alt="%2$s"
				class="wp-block-jetpack-story_image wp-story-image %3$s"
				src="%4$s"
			/>',
			esc_attr( $title ),
			esc_attr( $alt ),
			$width && $height ? get_image_crop_class( $width, $height ) : '',
			esc_attr( $media['url'] )
		);
	}

	$crop_class = get_image_crop_class( $width, $height );
	// need to specify the size of the embed so it picks an image that is large enough for the `src` attribute
	// `sizes` is optimized for 1080x1920 (9:16) images
	// Note that the Story block does not have thumbnail support, it will load the right
	// image based on the viewport size only.
	return wp_get_attachment_image(
		$media['id'],
		EMBED_SIZE,
		false,
		array(
			'class' => sprintf( 'wp-story-image wp-image-%d %s', $media['id'], $crop_class ),
			'sizes' => IMAGE_BREAKPOINTS,
			'title' => get_the_title( $media['id'] ),
		)
	);
}

/**
 * Return the css crop class if image width and height requires it
 *
 * @param int $width   - Image width.
 * @param int $height  - Image height.
 *
 * @returns string The CSS class which will display a cropped image
 */
function get_image_crop_class( $width, $height ) {
	$crop_class          = '';
	$media_aspect_ratio  = $width / $height;
	$target_aspect_ratio = EMBED_SIZE[0] / EMBED_SIZE[1];
	if ( $media_aspect_ratio >= $target_aspect_ratio ) {
		// image wider than canvas.
		$media_too_wide_to_crop = $media_aspect_ratio > $target_aspect_ratio / ( 1 - CROP_UP_TO );
		if ( ! $media_too_wide_to_crop ) {
			$crop_class = 'wp-story-crop-wide';
		}
	} else {
		// image narrower than canvas.
		$media_too_narrow_to_crop = $media_aspect_ratio < $target_aspect_ratio * ( 1 - CROP_UP_TO );
		if ( ! $media_too_narrow_to_crop ) {
			$crop_class = 'wp-story-crop-narrow';
		}
	}
	return $crop_class;
}

/**
 * Returns a URL for the site icon.
 *
 * @param int    $size - Size for (square) sitei icon.
 * @param string $fallback - Fallback URL to use if no site icon is found.
 *
 * @returns string
 */
function get_blavatar_or_site_icon_url( $size, $fallback ) {
	$image_array = Jetpack_PostImages::from_blavatar( get_the_ID(), $size );
	if ( ! empty( $image_array ) ) {
		return $image_array[0]['src'];
	} else {
		return $fallback;
	}
}

/**
 * Render a video inside a slide
 *
 * @param array $media  - Video information.
 *
 * @returns string
 */
function render_video( $media ) {
	if ( empty( $media['id'] ) || empty( $media['mime'] ) || empty( $media['url'] ) ) {
		return __( 'Error retrieving media', 'jetpack' );
	}

	if ( ! empty( $media['poster'] ) ) {
		return render_image(
			array_merge(
				$media,
				array(
					'type' => 'image',
					'url'  => $media['poster'],
				)
			)
		);
	}

	return sprintf(
		'<video
			title="%1$s"
			type="%2$s"
			class="wp-story-video intrinsic-ignore wp-video-%3$s"
			data-id="%3$s"
			src="%4$s">
		</video>',
		esc_attr( get_the_title( $media['id'] ) ),
		esc_attr( $media['mime'] ),
		$media['id'],
		esc_attr( $media['url'] )
	);
}

/**
 * Pick a thumbnail to render a static/embedded story
 *
 * @param array $media_files  - list of Media files.
 *
 * @returns string
 */
function render_static_slide( $media_files ) {
	$media_template = '';
	if ( empty( $media_files ) ) {
		return '';
	}

	// find an image to showcase.
	foreach ( $media_files as $media ) {
		switch ( $media['type'] ) {
			case 'image':
				$media_template = render_image( $media );
				break 2;
			case 'video':
				// ignore videos without a poster image.
				if ( empty( $media['poster'] ) ) {
					continue 2;
				}
				$media_template = render_video( $media );
				break 2;
		}
	}

	// if no "static" media was found for the thumbnail try to render a video tag without poster.
	if ( empty( $media_template ) && ! empty( $media_files ) ) {
		$media_template = render_video( $media_files[0] );
	}

	return sprintf(
		'<div class="wp-story-slide" style="display: block;">
			<figure>%s</figure>
		</div>',
		$media_template
	);
}

/**
 * Render the top right icon on top of the story embed
 *
 * @param array $settings  - The block settings.
 *
 * @returns string
 */
function render_top_right_icon( $settings ) {
	$show_slide_count = isset( $settings['showSlideCount'] ) ? $settings['showSlideCount'] : false;
	$slide_count      = isset( $settings['slides'] ) ? count( $settings['slides'] ) : 0;
	if ( $show_slide_count ) {
		// Render the story block icon along with the slide count.
		return sprintf(
			'<div class="wp-story-embed-icon">
				<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" role="img" aria-hidden="true" focusable="false">
					<path d="M0 0h24v24H0z" fill="none"></path>
					<path fill-rule="evenodd" clip-rule="evenodd" d="M6 3H14V17H6L6 3ZM4 3C4 1.89543 4.89543 1 6 1H14C15.1046 1 16 1.89543 16 3V17C16 18.1046 15.1046 19 14 19H6C4.89543 19 4 18.1046 4 17V3ZM18 5C19.1046 5 20 5.89543 20 7V21C20 22.1046 19.1046 23 18 23H10C8.89543 23 8 22.1046 8 21H18V5Z"></path>
				</svg>
				<span>%d</span>
			</div>',
			$slide_count
		);
	} else {
		// Render the Fullscreen Gridicon.
		return (
			'<div class="wp-story-embed-icon-expand">
				<svg class="gridicon gridicons-fullscreen" role="img" height="24" width="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
					<g>
						<path d="M21 3v6h-2V6.41l-3.29 3.3-1.42-1.42L17.59 5H15V3zM3 3v6h2V6.41l3.29 3.3 1.42-1.42L6.41 5H9V3zm18 18v-6h-2v2.59l-3.29-3.29-1.41 1.41L17.59 19H15v2zM9 21v-2H6.41l3.29-3.29-1.41-1.42L5 17.59V15H3v6z"></path>
					</g>
				</svg>
			</div>'
		);
	}
}

/**
 * Render a pagination bullet
 *
 * @param int    $slide_index  - The slide index it corresponds to.
 * @param string $class_name   - Optional css class name(s) to customize the bullet element.
 *
 * @returns string
 */
function render_pagination_bullet( $slide_index, $class_name = '' ) {
	return sprintf(
		'<div class="wp-story-pagination-bullet %s" aria-label="%s">
			<div class="wp-story-pagination-bullet-bar"></div>
		</div>',
		esc_attr( $class_name ),
		/* translators: %d is the slide number (1, 2, 3...) */
		sprintf( __( 'Go to slide %d', 'jetpack' ), $slide_index )
	);
}

/**
 * Render pagination on top of the story embed
 *
 * @param array $settings  - The block settings.
 *
 * @returns string
 */
function render_pagination( $settings ) {
	$show_slide_count = isset( $settings['showSlideCount'] ) ? $settings['showSlideCount'] : false;
	if ( $show_slide_count ) {
		return '';
	}
	$slide_count     = isset( $settings['slides'] ) ? count( $settings['slides'] ) : 0;
	$bullet_count    = min( $slide_count, MAX_BULLETS );
	$bullet_ellipsis = $slide_count > $bullet_count
		? render_pagination_bullet( $bullet_count + 1, 'wp-story-pagination-ellipsis' )
		: '';
	return sprintf(
		'<div class="wp-story-pagination wp-story-pagination-bullets">
			%s
		</div>',
		join( "\n", array_map( __NAMESPACE__ . '\render_pagination_bullet', range( 1, $bullet_count ) ) ) . $bullet_ellipsis
	);
}

/**
 * Render story block
 *
 * @param array $attributes  - Block attributes.
 *
 * @returns string
 */
function render_block( $attributes ) {
	// Let's use a counter to have a different id for each story rendered in the same context.
	static $story_block_counter = 0;

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	$media_files              = isset( $attributes['mediaFiles'] ) ? enrich_media_files( $attributes['mediaFiles'] ) : array();
	$settings_from_attributes = isset( $attributes['settings'] ) ? $attributes['settings'] : array();

	$settings = array_merge(
		$settings_from_attributes,
		array(
			'slides' => $media_files,
		)
	);

	return sprintf(
		'<div class="%1$s" data-id="%2$s" data-settings="%3$s">
			<div class="wp-story-app">
				<div class="wp-story-display-contents" style="display: contents;">
					<a class="wp-story-container" href="%4$s" title="%5$s">
						<div class="wp-story-meta">
							<div class="wp-story-icon">
								<img alt="%6$s" src="%7$s" width="40" height="40">
							</div>
							<div>
								<div class="wp-story-title">
									%8$s
								</div>
							</div>
						</div>
						<div class="wp-story-wrapper">
							%9$s
						</div>
						<div class="wp-story-overlay">
							%10$s
						</div>
						%11$s
					</a>
				</div>
			</div>
		</div>',
		esc_attr( Blocks::classes( FEATURE_NAME, $attributes, array( 'wp-story', 'aligncenter' ) ) ),
		esc_attr( 'wp-story-' . get_the_ID() . '-' . strval( ++$story_block_counter ) ),
		filter_var( wp_json_encode( $settings ), FILTER_SANITIZE_SPECIAL_CHARS ),
		get_permalink() . '?wp-story-load-in-fullscreen=true&amp;wp-story-play-on-load=true',
		__( 'Play story in new tab', 'jetpack' ),
		__( 'Site icon', 'jetpack' ),
		esc_attr( get_blavatar_or_site_icon_url( 80, includes_url( 'images/w-logo-blue.png' ) ) ),
		esc_html( get_the_title() ),
		render_static_slide( $media_files ),
		render_top_right_icon( $settings ),
		render_pagination( $settings )
	);
}
