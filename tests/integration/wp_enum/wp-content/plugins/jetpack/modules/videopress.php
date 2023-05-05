<?php
/**
 * Module Name: VideoPress
 * Module Description: Save on hosting storage and bandwidth costs by streaming fast, ad-free video from our global network.
 * First Introduced: 2.5
 * Requires Connection: Yes
 * Sort Order: 27
 * Module Tags: Photos and Videos
 * Feature: Writing
 * Additional Search Queries: video, videos, videopress, video gallery, video player, videoplayer, mobile video, vimeo, youtube, html5 video, stream
 *
 * @package automattic/jetpack
 */

/**
 * Require the VideoPress files.
 */
require_once __DIR__ . '/videopress/shortcode.php';
require_once __DIR__ . '/videopress/class.videopress-scheduler.php';
require_once __DIR__ . '/videopress/class.videopress-cli.php';
require_once __DIR__ . '/videopress/class.jetpack-videopress.php';

require_once __DIR__ . '/videopress/class-videopress-attachment-metadata.php';

if ( is_admin() ) {
	include_once __DIR__ . '/videopress/editor-media-view.php';
	include_once __DIR__ . '/videopress/class.videopress-edit-attachment.php';
}
