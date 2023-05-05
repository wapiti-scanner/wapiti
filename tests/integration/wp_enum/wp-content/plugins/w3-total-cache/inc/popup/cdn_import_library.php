<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/popup/common/header.php'; ?>

<script type="text/javascript">/*<![CDATA[*/
jQuery(function() {
	W3tc_Popup_Cdn_Import_Library.nonce = '<?php echo esc_html( wp_create_nonce( 'w3tc' ) ); ?>';
	W3tc_Popup_Cdn_Import_Library.cdn_host = '<?php echo esc_html( $cdn_host ); ?>';
	W3tc_Popup_Cdn_Import_Library.init();
});
/*]]>*/</script>

<p><?php esc_html_e( 'This tool will copy post or page attachments into the Media Library allowing WordPress to work as intended.', 'w3-total-cache' ); ?></p>
<table cellspacing="5">
	<tr>
		<td><?php esc_html_e( 'Total posts:', 'w3-total-cache' ); ?></td>
		<td id="cdn_import_library_total"><?php echo esc_html( $total ); ?></td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Processed:', 'w3-total-cache' ); ?></td>
		<td id="cdn_import_library_processed">0</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Status:', 'w3-total-cache' ); ?></td>
		<td id="cdn_import_library_status">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Time elapsed:', 'w3-total-cache' ); ?></td>
		<td id="cdn_import_library_elapsed">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Last response:', 'w3-total-cache' ); ?></td>
		<td id="cdn_import_library_last_response">-</td>
	</tr>
	<tr>
		<td colspan="2">
			<label><input id="cdn_import_library_redirect_permanent" type="checkbox" checked="checked" /> <?php esc_html_e( 'Create a list of permanent (301) redirects for use in your site\'s .htaccess file', 'w3-total-cache' ); ?></label>
		</td>
	</tr>
	<tr>
		<td colspan="2">
			<label>
				<input id="cdn_import_library_redirect_cdn" type="checkbox" />
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'Create a list of redirects to %1$sCDN%2$s (hostname specified in hostname field #1.)',
							'w3-total-cache'
						),
						'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">',
						'</acronym>'
					),
					array(
						'acronym' => array(
							'title' => array(),
						),
					)
				);
				?>
			</label>
		</td>
	</tr>
		<tr>
			<td colspan="2">
				<?php $config_state = Dispatcher::config_state(); ?>
				<label><input id="cdn_import_external" type="checkbox" name="cdn.import.external" <?php checked( $config_state->get_boolean( 'cdn.import.external' ), true ); ?>/> <?php Util_Ui::e_config_label( 'cdn.import.external' ); ?></label>
			</td>
		</tr>
</table>

<p>
	<input id="cdn_import_library_start" class="button-primary" type="button" value="<?php esc_attr_e( 'Start', 'w3-total-cache' ); ?>" <?php echo ! $total ? 'disabled="disabled"' : ''; ?>/>
</p>

<div id="cdn_import_library_progress" class="media-item">
	<div class="progress"><div class="bar"><div class="filename original"><span class="percent">0%</span></div></div></div>
	<div class="clear"></div>
</div>

<div id="cdn_import_library_log" class="log"></div>

<p>
	<?php esc_html_e( 'Add the following directives to your .htaccess file or if there are several hundred they should be added directly to your configuration file:', 'w3-total-cache' ); ?>
</p>

<p>
	<textarea rows="10" cols="90" id="cdn_import_library_rules" class="rules"></textarea>
</p>

<?php require W3TC_INC_DIR . '/popup/common/footer.php'; ?>
