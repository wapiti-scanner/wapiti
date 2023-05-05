<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_cdn_rackspace_form" method="post" style="padding: 20px">
	<?php Util_Ui::hidden( '', 'w3tc_action', 'cdn_rackspace_intro_done' ); ?>
	<?php
	if ( isset( $details['error_message'] ) ) {
		echo '<div class="error">' . esc_html( $details['error_message'] ) . '</div>';
	}
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Your RackSpace API key', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Username:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="user_name" type="text" class="w3tc-ignore-change"
						style="width: 100px" value="<?php echo esc_attr( $details['user_name'] ); ?>" />
				</td>
			</tr>
			<tr>
				<th>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sAPI%2$s key:',
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
				</th>
				<td>
					<input name="api_key" type="text" class="w3tc-ignore-change"
						style="width: 550px" value="<?php echo esc_attr( $details['api_key'] ); ?>" />
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
