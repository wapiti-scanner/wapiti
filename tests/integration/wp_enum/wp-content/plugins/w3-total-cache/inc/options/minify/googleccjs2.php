<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$compilation_levels = array(
	'WHITESPACE_ONLY'        => __( 'Whitespace only', 'w3-total-cache' ),
	'SIMPLE_OPTIMIZATIONS'   => __( 'Simple optimizations', 'w3-total-cache' ),
	'ADVANCED_OPTIMIZATIONS' => __( 'Advanced optimizations', 'w3-total-cache' ),
);

$compilation_level = $this->_config->get_string( 'minify.ccjs.options.compilation_level' );
?>
<tr>
	<th>&nbsp;</th>
	<td>
		<input class="minifier_test js_enabled button {type: 'googleccjs', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
			type="button" value="<?php esc_attr_e( 'Test Closure Compiler', 'w3-total-cache' ); ?>" />
		<span class="minifier_test_status w3tc-status w3tc-process"></span>
	</td>
</tr>
<tr>
	<th><label for="minify_ccjs_options_compilation_level"><?php Util_Ui::e_config_label( 'minify.ccjs.options.compilation_level' ); ?></label></th>
	<td>
		<select id="minify_ccjs_options_compilation_level" class="js_enabled" name="minify__ccjs__options__compilation_level"
			<?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
			<?php foreach ( $compilation_levels as $compilation_level_key => $compilation_level_name ) : ?>
				<option value="<?php echo esc_attr( $compilation_level_key ); ?>" <?php selected( $compilation_level, $compilation_level_key ); ?>>
					<?php echo esc_html( $compilation_level_name ); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</td>
</tr>
<tr>
	<th></th>
	<td>
		<input type="hidden" name="minify__ccjs__options__formatting" value="" />
		<label>
			<input class="js_enabled" type="checkbox" name="minify__ccjs__options__formatting"
				value="pretty_print"
				<?php checked( $this->_config->get_string( 'minify.ccjs.options.formatting' ), 'pretty_print' ); ?>
				<?php Util_Ui::sealing_disabled( 'minify.' ); ?> /> <?php Util_Ui::e_config_label( 'minify.ccjs.options.formatting' ); ?>
		</label>
	</td>
</tr>
