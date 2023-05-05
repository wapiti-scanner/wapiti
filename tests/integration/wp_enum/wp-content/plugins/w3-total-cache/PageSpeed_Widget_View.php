<?php
/**
 * File: PageSpeed_Widget_View.php
 *
 * Default PageSpeed dashboard widget template.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div class="w3tcps_loading w3tc_none">
	<span class="spinner"></span>
	<p><?php esc_html_e( 'Running Analysis. This may take up to 2 minutes.', 'w3-total-cache' ); ?></p>
</div>
<div class="w3tcps_error w3tc_none notice notice-error"></div>
<div class="w3tcps_missing_token w3tc_none"></div>
<div class="w3tc-gps-widget"></div>
<div class="w3tcps_timestamp_container">
	<p class="w3tcps_timestamp_label">
		<?php esc_html_e( 'Analysis last run ', 'w3-total-cache' ); ?>
		<span class="w3tcps_timestamp"></span>
	</p>
</div>
<div class="w3tcps_buttons w3tc_none">
	<input class="button w3tcps_refresh" type="button" value="<?php esc_html_e( 'Refresh Analysis', 'w3-total-cache' ); ?>" />
	<a href="<?php echo esc_url( admin_url( 'admin.php?page=w3tc_pagespeed' ) ); ?>" class="button"><?php esc_html_e( 'View All Results', 'w3-total-cache' ); ?></a>
</div>
