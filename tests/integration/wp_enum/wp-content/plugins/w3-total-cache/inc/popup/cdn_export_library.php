<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/popup/common/header.php'; ?>

<script type="text/javascript">/*<![CDATA[*/
jQuery(function() {
	W3tc_Popup_Cdn_Export_Library.nonce = '<?php echo esc_html( wp_create_nonce( 'w3tc' ) ); ?>';
	W3tc_Popup_Cdn_Export_Library.init();
});
/*]]>*/</script>

<p><?php esc_html_e( 'This tool will upload files of the selected type to content delivery network provider.', 'w3-total-cache' ); ?></p>
<table cellspacing="5">
	<tr>
		<td><?php esc_html_e( 'Total media library attachments:', 'w3-total-cache' ); ?></td>
		<td id="cdn_export_library_total"><?php echo esc_html( $total ); ?></td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Processed:', 'w3-total-cache' ); ?></td>
		<td id="cdn_export_library_processed">0</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Status:', 'w3-total-cache' ); ?></td>
		<td id="cdn_export_library_status">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Time elapsed:', 'w3-total-cache' ); ?></td>
		<td id="cdn_export_library_elapsed">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Last response:', 'w3-total-cache' ); ?></td>
		<td id="cdn_export_library_last_response">-</td>
	</tr>
</table>

<p>
	<input id="cdn_export_library_start" class="button-primary" type="button" value="<?php esc_html_e( 'Start', 'w3-total-cache' ); ?>" <?php echo ! $total ? 'disabled="disabled"' : ''; ?>/>
</p>

<div id="cdn_export_library_progress" class="media-item">
	<div class="progress"><div class="bar"><div class="filename original"><span class="percent">0%</span></div></div></div>
	<div class="clear"></div>
</div>

<div id="cdn_export_library_log" class="log"></div>

<?php require W3TC_INC_DIR . '/popup/common/footer.php'; ?>
