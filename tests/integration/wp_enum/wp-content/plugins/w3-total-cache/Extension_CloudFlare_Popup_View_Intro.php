<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_extension_cloudflare_form" method="post" style="padding: 20px">
	<?php Util_Ui::hidden( '', 'w3tc_action', 'extension_cloudflare_intro_done' ); ?>
	<?php
	if ( isset( $details['error_message'] ) ) {
		echo '<div class="error">' . esc_html( $details['error_message'] ) . '</div>';
	}
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Your CloudFlare API token / global key', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Email:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="email" type="text" class="w3tc-ignore-change"
						style="width: 300px"
						value="<?php echo esc_attr( $details['email'] ); ?>" />
				</td>
			</tr>
			<tr>
				<th>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sAPI%2$s token / global key:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</td>
				<td>
					<input name="key" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $details['key'] ); ?>" />
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_popup_submit w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Next', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
