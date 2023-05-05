<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php Util_Ui::postbox_header( esc_html__( 'Opcode Cache', 'w3-total-cache' ), '', 'system_opcache' ); ?>

<table class="form-table">
	<?php
	Util_Ui::config_item(
		array(
			'key'              => 'opcache.engine',
			'label'            => esc_html__( 'Opcode Cache', 'w3-total-cache' ),
			'control'          => 'selectbox',
			'value'            => $opcode_engine,
			'selectbox_values' => array(
				'Not Available' => array(
					'disabled' => ( 'Not Available' !== $opcode_engine ),
					'label'    => esc_html__( 'Not Available', 'w3-total-cache' ),
				),
				'OPcache'       => array(
					'disabled' => ( 'OPcache' !== $opcode_engine ),
					'label'    => esc_html__( 'Opcode: Zend Opcache', 'w3-total-cache' ),
				),
				'APC'           => array(
					'disabled' => ( 'APC' !== $opcode_engine ),
					'label'    => esc_html__( 'Opcode: Alternative PHP Cache (APC / APCu)', 'w3-total-cache' ),
				),
			),
		)
	);
	Util_Ui::config_item(
		array(
			'key'            => 'opcache.validate_timestamps',
			'label'          => 'Validate timestamps:',
			'control'        => 'checkbox',
			'disabled'       => true,
			'value'          => $validate_timestamps,
			'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
			'description'    => esc_html__( 'Once enabled, each file request will update the cache with the latest version. When this setting is off, the Opcode Cache will not check, instead PHP must be restarted in order for setting changes to be reflected.', 'w3-total-cache' )
		)
	);
	?>
</table>
<?php
Util_Ui::button_config_save(
	'general_opcache',
	'<input type="submit" name="w3tc_opcache_flush" value="' . esc_attr__( 'Empty cache', 'w3-total-cache' ) . '"' .
		( ( 'Not Available' !== $opcode_engine ) ? '' : ' disabled="disabled" ' ) . ' class="button" />'
);
?>

<?php Util_Ui::postbox_footer(); ?>
