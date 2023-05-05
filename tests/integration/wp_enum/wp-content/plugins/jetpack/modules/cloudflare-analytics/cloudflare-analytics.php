<?php
/**
 * Cloudflare Analytics
 * Let WPCOM users automatically insert a Cloudflare analytics JS snippet into their site header.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Cloudflare_Analytics;

use Automattic\Jetpack\Status\Host;

/**
 * Add Cloudflare Analytics tracking code to the head.
 * This is currently only available to Atomic and WordPress.com Simple sites.
 *
 * @since 9.5.0
 */
function insert_tracking_id() {
	$option = get_option( 'jetpack_cloudflare_analytics' );

	if (
		! empty( $option['code'] )
		&& ! is_admin()
		&& ( class_exists( 'Jetpack_AMP_Support' ) && ! \Jetpack_AMP_Support::is_amp_request() )
		&& ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || ( new Host() )->is_woa_site() )
	) {
		// phpcs:disable WordPress.WP.EnqueuedResources.NonEnqueuedScript
		printf(
			"<!-- Jetpack Cloudflare Web Analytics -->
<script defer
	src='https://static.cloudflareinsights.com/beacon.min.js'
	data-cf-beacon='{\"token\": \"%s\"}'>
</script>
<!-- End Jetpack Cloudflare Web Analytics -->\r\n",
			esc_html( $option['code'] )
		);
		// phpcs:enable WordPress.WP.EnqueuedResources.NonEnqueuedScript
	}
}
add_action( 'wp_footer', __NAMESPACE__ . '\insert_tracking_id', 999 );
