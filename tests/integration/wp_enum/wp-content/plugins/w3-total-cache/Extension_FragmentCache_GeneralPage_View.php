<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

Util_Ui::postbox_header( 'Fragment Cache', '', 'fragmentcache' );
?>
<p><?php esc_html_e( 'Enable fragment caching reduce execution time for common operations.', 'w3-total-cache' ); ?></p>

<table class="form-table">
	<?php
	Util_Ui::config_item_engine(
		array(
			'key'         => array( 'fragmentcache', 'engine' ),
			'label'       => __( 'Fragment Cache Method:', 'w3-total-cache' ),
			'empty_value' => true,
		)
	);
	?>
</table>

<?php
Util_Ui::button_config_save(
	'general_fragmentcache',
	'<input type="submit" name="w3tc_flush_fragmentcache" value="' . __( 'Empty cache', 'w3-total-cache' ) . '" class="button" />'
);
?>
<?php Util_Ui::postbox_footer(); ?>
