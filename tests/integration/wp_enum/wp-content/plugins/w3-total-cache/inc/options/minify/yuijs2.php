<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<tr>
	<th><label for="minify__yuijs__path__java"><?php esc_html_e( 'Path to JAVA executable:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="minify__yuijs__path__java" class="js_enabled" type="text"
			<?php Util_Ui::sealing_disabled( 'minify.' ); ?> name="minify__yuijs__path__java"
			value="<?php echo esc_attr( $this->_config->get_string( 'minify.yuijs.path.java' ) ); ?>"
			size="100" />
	</td>
</tr>
<tr>
	<th><label for="minify__yuijs__path__jar"><?php esc_html_e( 'Path to JAR file:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="minify__yuijs__path__jar" class="js_enabled" type="text"
			<?php Util_Ui::sealing_disabled( 'minify.' ); ?> name="minify__yuijs__path__jar"
			value="<?php echo esc_attr( $this->_config->get_string( 'minify.yuijs.path.jar' ) ); ?>"
			size="100" />
	</td>
</tr>
<tr>
	<th>&nbsp;</th>
	<td>
		<input class="minifier_test button js_enabled {type: 'yuijs', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
			type="button" value="<?php esc_attr_e( 'Test YUI Compressor', 'w3-total-cache' ); ?>" />
		<span class="minifier_test_status w3tc-status w3tc-process"></span>
	</td>
</tr>
<tr>
	<th><label for="minify__yuijs__options__line-break"><?php Util_Ui::e_config_label( 'minify.yuijs.options.line-break' ); ?></label></th>
	<td>
		<input id="minify__yuijs__options__line-break" class="js_enabled"
			type="text" <?php Util_Ui::sealing_disabled( 'minify.' ); ?>
			name="minify__yuijs__options__line-break" value="<?php echo esc_attr( $this->_config->get_integer( 'minify.yuijs.options.line-break' ) ); ?>"
			size="8" style="text-align: right;" /> <?php esc_html_e( 'symbols (set to 0 to disable)', 'w3-total-cache' ); ?>
	</td>
</tr>
