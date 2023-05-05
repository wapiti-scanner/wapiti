<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php Util_Ui::postbox_header( esc_html__( 'Network Performance &amp; Security powered by CloudFlare', 'w3-total-cache' ), '', 'cloudflare' ); ?>
<?php Util_Ui::config_overloading_button( array( 'key' => 'cloudflare.configuration_overloaded' ) ); ?>
<p>
	<?php esc_html_e( 'CloudFlare protects and accelerates websites.', 'w3-total-cache' ); ?>
</p>

<table class="form-table">
	<?php
	Util_Ui::config_item(
		array(
			'key'         => array( 'cloudflare', 'widget_cache_mins' ),
			'label'       => esc_html__( 'Cache time:', 'w3-total-cache' ),
			'control'     => 'textbox',
			'description' => esc_html__( 'How many minutes data retrieved from CloudFlare should be stored. Minimum is 1 minute.', 'w3-total-cache' ),
		)
	);

	Util_Ui::config_item(
		array(
			'key'            => array( 'cloudflare', 'pagecache' ),
			'label'          => esc_html__( 'Page Caching:', 'w3-total-cache' ),
			'control'        => 'checkbox',
			'checkbox_label' => esc_html__( 'Flush CloudFlare on Post Modifications', 'w3-total-cache' ),
			'description'    => esc_html__( 'Enable when you have html pages cached on CloudFlare level.', 'w3-total-cache' ),
		)
	);
	?>
</table>

<?php
Util_Ui::button_config_save(
	'general_cloudflare',
	'<input type="submit" name="w3tc_cloudflare_flush" value="' . esc_attr__( 'Empty cache', 'w3-total-cache' ) . '" class="button" />'
);
?>
<?php Util_Ui::postbox_footer(); ?>
