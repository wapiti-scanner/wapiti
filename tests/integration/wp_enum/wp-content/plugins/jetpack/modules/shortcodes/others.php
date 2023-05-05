<?php
/**
 * Extra oEmbed providers that we use on wpcom for feature parity.
 *
 * This file will be loaded even when you don't use the Shortcodes feature,
 * as these embeds are considered safe to use on any site
 * (and may end up embedded in Core in the future).
 *
 * @package automattic/jetpack
 */

wp_oembed_add_provider( 'https://me.sh/*', 'https://me.sh/oembed?format=json' );
wp_oembed_add_provider( '#https?://(www\.)?gfycat\.com/.*#i', 'https://api.gfycat.com/v1/oembed', true );
wp_oembed_add_provider( '#https?://[^.]+\.(wistia\.com|wi\.st)/(medias|embed)/.*#', 'https://fast.wistia.com/oembed', true );
wp_oembed_add_provider( '#https?://sketchfab\.com/.*#i', 'https://sketchfab.com/oembed', true );
wp_oembed_add_provider( '#https?://(www\.)?icloud\.com/keynote/.*#i', 'https://iwmb.icloud.com/iwmb/oembed', true );
wp_oembed_add_provider( '#https?://(www\.)?icloud\.com\.cn/keynote/.*#i', 'https://iwmb.icloud.com.cn/iwmb/oembed', true );
wp_oembed_add_provider( '#https?://((song|album|artist|pods|playlist)\.link|odesli\.com?|mylink\.page)/.*#', 'https://odesli.co/oembed', true );
wp_oembed_add_provider( '#https?://(www\.)?loom\.com/share/.*#i', 'https://www.loom.com/v1/oembed', true );

/**
 * Filters the HTTP request timeout value so that we can increase the timeout for iCloud oEmbeds.
 *
 * @param int    $timeout The timeout value in seconds.
 * @param string $url     The URL to fetch.
 *
 * @return int The timeout value in seconds.
 */
function jetpack_oembed_timeout_override( $timeout, $url ) {
	if ( false !== strpos( $url, 'iwmb.icloud.com' ) ) {
		return 10;
	}
	return $timeout;
}

// TODO: Remove this. This should hopefully be a temporary hack since Apple's oEmbed often seems to take more than 5 seconds to respond. 10 is an arbitrary number of seconds that seems to work better.
add_filter( 'http_request_timeout', 'jetpack_oembed_timeout_override', 10, 2 );

// WordPress core only registers pca.st, not pcast.pocketcasts.net.
wp_oembed_add_provider( '#https?://pcast\.pocketcasts\.net/.+#i', 'https://pcast.pocketcasts.net/oembed.json', true );
