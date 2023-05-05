<?php
/**
 * Heading for geolocation settings page.
 *
 * @since 1.6.6
 *
 * @var bool $plugin_allow Allow using plugin.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<h4>
	<?php esc_html_e( 'Geolocation', 'wpforms-lite' ); ?>
	<?php if ( ! $plugin_allow ) { ?>
		<img
			src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-settings-access/pro-plus.svg' ); ?>"
			alt="<?php esc_attr_e( 'Pro+', 'wpforms-lite' ); ?>"
		>
	<?php } ?>
</h4>
<p><?php esc_html_e( 'Do you want to learn more about visitors who fill out your online forms? Our geolocation addon allows you to collect and store your website visitors geolocation data along with their form submission. This insight can help you to be better informed and turn more leads into customers. Furthermore, add a smart address field that autocompletes using the Google Places API.', 'wpforms-lite' ); ?></p>
