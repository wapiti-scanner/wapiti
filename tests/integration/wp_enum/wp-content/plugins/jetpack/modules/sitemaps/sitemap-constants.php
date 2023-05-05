<?php
/**
 * Sitemap-related constants.
 *
 * @package automattic/jetpack
 * @since 4.8.0
 * @author Automattic
 */

/**
 * Number of seconds between sitemap and news sitemap updates in development code.
 * In production, sitemaps are cached for 12 hours.
 * In development, sitemaps are cache for 1 minute.
 *
 * @since 7.7.0
 */
if ( defined( 'JETPACK_DEV_DEBUG' ) && JETPACK_DEV_DEBUG ) {
	if ( ! defined( 'JP_SITEMAP_INTERVAL' ) ) {
		define( 'JP_SITEMAP_INTERVAL', 60 );
	}
	if ( ! defined( 'JP_NEWS_SITEMAP_INTERVAL' ) ) {
		define( 'JP_NEWS_SITEMAP_INTERVAL', 60 );
	}
}

/**
 * Maximum size (in bytes) of a sitemap xml file.
 * Max is 716800 = 700kb to avoid potential failures for default memcached limits (1MB)
 *
 * @link https://www.sitemaps.org/
 * @since 4.8.0
 */
if ( ! defined( 'JP_SITEMAP_MAX_BYTES' ) ) {
	define( 'JP_SITEMAP_MAX_BYTES', 716800 );
}

/**
 * Maximum size (in url nodes) of a sitemap xml file.
 * Per the spec, max value is 50000.
 *
 * @link https://www.sitemaps.org/
 * @since 4.8.0
 */
if ( ! defined( 'JP_SITEMAP_MAX_ITEMS' ) ) {
	define( 'JP_SITEMAP_MAX_ITEMS', 2000 );
}

/**
 * Maximum size (in url nodes) of a news sitemap xml file.
 * Per the spec, max value is 1000.
 *
 * @link https://support.google.com/news/publisher/answer/74288?hl=en
 * @since 4.8.0
 */
if ( ! defined( 'JP_NEWS_SITEMAP_MAX_ITEMS' ) ) {
	define( 'JP_NEWS_SITEMAP_MAX_ITEMS', 1000 );
}

/**
 * Batch size for database queries.
 *
 * @since 4.8.0
 */
if ( ! defined( 'JP_SITEMAP_BATCH_SIZE' ) ) {
	define( 'JP_SITEMAP_BATCH_SIZE', 50 );
}

/**
 * Number of sitemap files to update on each run.
 *
 * @since 4.8.0
 */
if ( ! defined( 'JP_SITEMAP_UPDATE_SIZE' ) ) {
	define( 'JP_SITEMAP_UPDATE_SIZE', 100 );
}

/**
 * Number of seconds between sitemap updates.
 *
 * @since 4.8.0
 */
if ( ! defined( 'JP_SITEMAP_INTERVAL' ) ) {
	define( 'JP_SITEMAP_INTERVAL', 12 * HOUR_IN_SECONDS );
}

/**
 * Number of seconds to lock the sitemap state.
 *
 * @since 4.8.0
 */
if ( ! defined( 'JP_SITEMAP_LOCK_INTERVAL' ) ) {
	define( 'JP_SITEMAP_LOCK_INTERVAL', 15 * MINUTE_IN_SECONDS );
}

/**
 * Number of seconds between news sitemap updates.
 *
 * @since 4.8.0
 */
if ( ! defined( 'JP_NEWS_SITEMAP_INTERVAL' ) ) {
	define( 'JP_NEWS_SITEMAP_INTERVAL', 12 * HOUR_IN_SECONDS );
}

/*
 * These constants represent the types of various kinds of sitemaps.
 * Note: these strings are used as 'post_types' in the database, and
 * so must be at most 20 characters long.
 */

if ( ! defined( 'JP_MASTER_SITEMAP_TYPE' ) ) {
	define( 'JP_MASTER_SITEMAP_TYPE', 'jp_sitemap_master' );
}

if ( ! defined( 'JP_PAGE_SITEMAP_TYPE' ) ) {
	define( 'JP_PAGE_SITEMAP_TYPE', 'jp_sitemap' );
}

if ( ! defined( 'JP_PAGE_SITEMAP_INDEX_TYPE' ) ) {
	define( 'JP_PAGE_SITEMAP_INDEX_TYPE', 'jp_sitemap_index' );
}

if ( ! defined( 'JP_IMAGE_SITEMAP_TYPE' ) ) {
	define( 'JP_IMAGE_SITEMAP_TYPE', 'jp_img_sitemap' );
}

if ( ! defined( 'JP_IMAGE_SITEMAP_INDEX_TYPE' ) ) {
	define( 'JP_IMAGE_SITEMAP_INDEX_TYPE', 'jp_img_sitemap_index' );
}

if ( ! defined( 'JP_VIDEO_SITEMAP_TYPE' ) ) {
	define( 'JP_VIDEO_SITEMAP_TYPE', 'jp_vid_sitemap' );
}

if ( ! defined( 'JP_VIDEO_SITEMAP_INDEX_TYPE' ) ) {
	define( 'JP_VIDEO_SITEMAP_INDEX_TYPE', 'jp_vid_sitemap_index' );
}

/**
 * The name (with extension) of a sitemap file of the given
 * type and number.
 *
 * @since 4.8.0
 *
 * @param string $type The sitemap type.
 * @param string $number The sitemap number.
 *
 * @return string The filename.
 */
function jp_sitemap_filename( $type, $number = null ) {
	if ( $number === null ) {
		return "error-not-int-$type-$number.xml";
	} elseif ( JP_MASTER_SITEMAP_TYPE === $type ) {
		return 'sitemap.xml';
	} elseif ( JP_PAGE_SITEMAP_TYPE === $type ) {
		return "sitemap-$number.xml";
	} elseif ( JP_PAGE_SITEMAP_INDEX_TYPE === $type ) {
		return "sitemap-index-$number.xml";
	} elseif ( JP_IMAGE_SITEMAP_TYPE === $type ) {
		return "image-sitemap-$number.xml";
	} elseif ( JP_IMAGE_SITEMAP_INDEX_TYPE === $type ) {
		return "image-sitemap-index-$number.xml";
	} elseif ( JP_VIDEO_SITEMAP_TYPE === $type ) {
		return "video-sitemap-$number.xml";
	} elseif ( JP_VIDEO_SITEMAP_INDEX_TYPE === $type ) {
		return "video-sitemap-index-$number.xml";
	} else {
		return "error-bad-type-$type-$number.xml";
	}
}

/**
 * The index type corresponding to a sitemap type.
 *
 * @since 4.8.0
 *
 * @param string $type The sitemap type.
 *
 * @return string The index type.
 */
function jp_sitemap_index_type_of( $type ) {
	if ( JP_PAGE_SITEMAP_TYPE === $type ) {
		return JP_PAGE_SITEMAP_INDEX_TYPE;
	} elseif ( JP_IMAGE_SITEMAP_TYPE === $type ) {
		return JP_IMAGE_SITEMAP_INDEX_TYPE;
	} elseif ( JP_VIDEO_SITEMAP_TYPE === $type ) {
		return JP_VIDEO_SITEMAP_INDEX_TYPE;
	} else {
		return "error-bad-type-$type";
	}
}

/**
 * The sitemap type corresponding to an index type.
 *
 * @since 4.8.0
 *
 * @param string $type The index type.
 *
 * @return string The sitemap type.
 */
function jp_sitemap_child_type_of( $type ) {
	if ( JP_PAGE_SITEMAP_INDEX_TYPE === $type ) {
		return JP_PAGE_SITEMAP_TYPE;
	} elseif ( JP_IMAGE_SITEMAP_INDEX_TYPE === $type ) {
		return JP_IMAGE_SITEMAP_TYPE;
	} elseif ( JP_VIDEO_SITEMAP_INDEX_TYPE === $type ) {
		return JP_VIDEO_SITEMAP_TYPE;
	} else {
		return "error-bad-type-$type";
	}
}

/**
 * Convert '0000-00-00 00:00:00' to '0000-00-00T00:00:00Z'.
 * Note that the input is assumed to be in UTC (a.k.a. GMT).
 *
 * @link https://www.w3.org/TR/NOTE-datetime
 * @since 4.8.0
 *
 * @param string $datetime The timestamp to convert.
 *
 * @return string The converted timestamp.
 */
function jp_sitemap_datetime( $datetime ) {
	$regex = '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/';

	if ( preg_match( $regex, $datetime ) ) {
		return str_replace( ' ', 'T', $datetime ) . 'Z';
	} else {
		return $datetime;
	}
}
