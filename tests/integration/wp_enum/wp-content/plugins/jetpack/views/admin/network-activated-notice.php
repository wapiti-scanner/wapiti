<?php
/**
 * View template file for network activation notice.
 *
 * @package automattic/jetpack
 */

if ( isset( $_GET['jetpack-notice'] ) && 'dismiss' === $_GET['jetpack-notice'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	?>
<div id="message" class="error">
	<p><?php esc_html_e( 'Jetpack is network activated and notices can not be dismissed.', 'jetpack' ); ?></p>
</div>
	<?php
}
