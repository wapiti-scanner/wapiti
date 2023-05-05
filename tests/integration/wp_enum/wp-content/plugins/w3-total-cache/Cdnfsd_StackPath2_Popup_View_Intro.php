<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_cdn_stackpath2_fsd_form">
	<?php
	if ( isset( $details['error_message'] ) ) {
		echo '<div class="error">' . esc_html( $details['error_message'] ) . '</div>';
	}
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Your StackPath Account credentials', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>API Client ID:</td>
				<td>
					<input name="client_id" type="text" class="w3tc-ignore-change"
						style="width: 550px" value="<?php echo esc_attr( $details['client_id'] ); ?>" />
				</td>
			</tr>
			<tr>
				<td>API Client Secret:</td>
				<td>
					<input name="client_secret" type="text" class="w3tc-ignore-change"
						style="width: 550px" value="<?php echo esc_attr( $details['client_secret'] ); ?>" />
					<p class="description">
						To obtain API key you can
						<a target="_blank" href="<?php echo esc_url( $url_obtain_key ); ?>">click here</a>,
						log in, and paste the key in above field.
					</p>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath2_fsd_list_stacks w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Next', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
