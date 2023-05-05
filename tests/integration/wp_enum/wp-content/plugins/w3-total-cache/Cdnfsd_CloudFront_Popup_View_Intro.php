<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_popup_form">
	<?php
	if ( isset( $details['error_message'] ) ) {
		echo '<div class="error">' . esc_html( $details['error_message'] ) . '</div>';
	}
	?>
	<div class="metabox-holder">
		<?php
		Util_Ui::postbox_header(
			wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Your %1$sAWS%2$s CloudFront Account Credentials',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Amazon Web Services', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			)
		);
		?>
		<table class="form-table">
			<tr>
				<td><?php esc_html_e( 'Access Key:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="access_key" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdnfsd.cloudfront.access_key' ) ); ?>" />
				</td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'Access Secret:', 'w3-total-cache' ); ?></td>
					<td>
						<input name="secret_key" type="text" class="w3tc-ignore-change"
							style="width: 550px"
							value="<?php echo esc_attr( $config->get_string( 'cdnfsd.cloudfront.secret_key' ) ); ?>" />
					</td>
				</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_cloudfront_fsd_list_distributions w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Next', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
