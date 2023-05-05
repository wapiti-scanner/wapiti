<?php
/**
 * Register VideoPress Video block.
 *
 * @package automattic/jetpack
 **/

namespace Automattic\Jetpack\Extensions\VideoPress_Video;

use Automattic\Jetpack\VideoPress\Initializer as VideoPress_Pkg_Initializer;

// Set the videopress/video block availability, depending on the site plan.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_availability_for_plan( 'videopress/video' );
	}
);

// Register the videopress/video block.
add_action(
	'init',
	function () {
		$extensions                            = \Jetpack_Gutenberg::get_extensions();
		$is_videopress_video_extension_enabled = in_array( 'videopress/video', $extensions, true );

		if (
			$is_videopress_video_extension_enabled &&
			method_exists( 'Automattic\Jetpack\VideoPress\Initializer', 'register_videopress_video_block' )
		) {
			VideoPress_Pkg_Initializer::register_videopress_video_block();
		}
	}
);

// Register the `v6-video-frame-poster` extension.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_extension_available( 'v6-video-frame-poster' );
	}
);
