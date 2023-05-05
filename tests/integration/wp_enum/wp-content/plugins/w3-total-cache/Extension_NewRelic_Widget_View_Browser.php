<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php esc_html_e( 'Metrics are not available for browser applications', 'w3-total-cache' ); ?>
<p>
	<a href="<?php echo esc_url( W3TC_NEWRELIC_SIGNUP_URL ); ?>" target="_blank">
		<?php esc_html_e( 'Upgrade your New Relic account to enable more metrics.', 'w3-total-cache' ); ?>
	</a>
</p>
