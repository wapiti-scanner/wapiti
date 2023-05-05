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
		<?php Util_Ui::postbox_header( esc_html__( 'Your LimeLight Account credentials', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td><?php esc_html_e( 'Account Short Name:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="short_name" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdn.limelight.short_name' ) ); ?>" />
				</td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'Username:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="username" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdn.limelight.username' ) ); ?>" />
				</td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'API Key:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="api_key" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdn.limelight.api_key' ) ); ?>" />
				</td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'CDN hostname:', 'w3-total-cache' ); ?></td>
				<td>
					<input name="domain" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $domain ); ?>" />
				</td>
			</tr>
		</table>
		<p class="submit">
			<input type="button"
				class="w3tc_cdn_limelight_save w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Next', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
