<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_popup_form" method="post">
	<?php
	Util_Ui::hidden( '', 'api_key', $details['api_key'] );
	Util_Ui::hidden( '', 'zone_id', $details['zone_id'] );
	Util_Ui::hidden( '', 'name', $details['name'] );
	?>

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Configure zone', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Name:', 'w3-total-cache' ); ?></th>
				<td><?php echo esc_html( $details['name'] ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Origin URL:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_value_change( $details, 'url' ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Origin IP:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_ip_change( $details, 'ip' ); ?>
					<p class="description"><?php esc_html_e( 'IP of your WordPress host', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Origin IP Resolution:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_boolean_change( $details, 'dns_check' ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Ignore Cache Control:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_boolean_change( $details, 'dns_check' ); ?></td>
			</tr>
			<tr>
				<th>
					<acronym title="<?php esc_attr_e( 'Content Delivery Network', 'w3-total-cache' ); ?>">
						<?php esc_html_e( 'CDN', 'w3-total-cache' ); ?>
					</acronym><?php esc_html_e( ' Domain:', 'w3-total-cache' ); ?>
				</th>
				<td>
					<?php $this->render_zone_value_change( $details, 'custom_domain' ); ?>
					<p class="description">
						<?php esc_html_e( 'Domain ', 'w3-total-cache' ); ?>
						<acronym title="<?php esc_attr_e( 'Content Delivery Network', 'w3-total-cache' ); ?>">
							<?php esc_html_e( 'CDN', 'w3-total-cache' ); ?>
						</acronym><?php esc_html_e( ' will handle', 'w3-total-cache' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath_fsd_configure_zone w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
			<input type="button"
				class="w3tc_cdn_stackpath_fsd_configure_zone_skip w3tc-button-save button"
				value="<?php esc_attr_e( 'Don\'t reconfigure, I know what I\'m doing', 'w3-total-cache' ); ?>" />

		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
