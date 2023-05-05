<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/popup/common/header.php'; ?>

<script type="text/javascript">/*<![CDATA[*/
jQuery(function() {
	W3tc_Popup_Cdn_Rename_Domain.nonce = '<?php echo esc_html( wp_create_nonce( 'w3tc' ) ); ?>';
	W3tc_Popup_Cdn_Rename_Domain.init('');
});
/*]]>*/</script>

<p>
	<?php
	echo wp_kses(
		sprintf(
			// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
			__(
				'This tool allows you to modify the URL of Media Library attachments. Use it if the "WordPress address (%1$sURL%2$s)" value has been changed in the past.',
				'w3-total-cache'
			),
			'<acronym title="' . __( 'Uniform Resource Indicator', 'w3-total-cache' ) . '">',
			'</acronym>'
		),
		array(
			'acronym' => array(
				'title' => array(),
			),
		)
	);
	?>
</p>
<table cellspacing="5">
	<tr>
		<td><?php esc_html_e( 'Total posts:', 'w3-total-cache' ); ?></td>
		<td id="cdn_rename_domain_total"><?php echo esc_html( $total ); ?></td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Processed:', 'w3-total-cache' ); ?></td>
		<td id="cdn_rename_domain_processed">0</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Status:', 'w3-total-cache' ); ?></td>
		<td id="cdn_rename_domain_status">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Time elapsed:', 'w3-total-cache' ); ?></td>
		<td id="cdn_rename_domain_elapsed">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Last response:', 'w3-total-cache' ); ?></td>
		<td id="cdn_rename_domain_last_response">-</td>
	</tr>
	<tr>
		<td><?php esc_html_e( 'Domains to rename:', 'w3-total-cache' ); ?></td>
		<td>
			<textarea cols="40" rows="3" id="cdn_rename_domain_names"></textarea><br />
			<?php esc_html_e( 'e.g.: domain.com', 'w3-total-cache' ); ?>
		</td>
	</tr>
</table>

<p>
	<input id="cdn_rename_domain_start" class="button-primary" type="button" value="<?php esc_html_e( 'Start', 'w3-total-cache' ); ?>" <?php echo ! $total ? 'disabled="disabled"' : ''; ?>/>
</p>

<div id="cdn_rename_domain_progress" class="media-item">
	<div class="progress"><div class="bar"><div class="filename original"><span class="percent">0%</span></div></div></div>
	<div class="clear"></div>
</div>

<div id="cdn_rename_domain_log" class="log"></div>

<?php require W3TC_INC_DIR . '/popup/common/footer.php'; ?>
