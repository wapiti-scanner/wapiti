<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_popup_form" method="post">
	<?php
	Util_Ui::hidden( '', 'access_key', $details['access_key'] );
	Util_Ui::hidden( '', 'secret_key', $details['secret_key'] );
	Util_Ui::hidden( '', 'distribution_id', $details['distribution_id'] );
	Util_Ui::hidden( '', 'distribution_comment', $details['distribution_comment'] );
	?>

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Configure distribution', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th>Distribution:</th>
				<td><?php echo esc_html( $details['distribution_comment'] ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Origin:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_ip_change( $details, 'origin' ); ?>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
								// translators: 5 HTML line break tag, 6 HTML line break tag,
								// translators: 7 opening HTML acronym tag, 8 closing HTML acronym tag.
								__(
									'Create an apex %1$sDNS%2$s record pointing to your WordPress host %3$sIP%4$s.%5$sCloudFront will use this host to mirror your site.%6$sTip: If your real domain name is domain.com, then the host for the apex record should be origin.domain.com with the host %7$sIP%8$s of domain.com, e.g.:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Domain Name System', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'Internet Protocol', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<br />',
								'<br />',
								'<acronym title="' . esc_attr__( 'Internet Protocol', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
								'br'      => array(),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Forward Cookies:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_boolean_change( $details, 'forward_cookies' ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Forward Query String:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_boolean_change( $details, 'forward_querystring' ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Forward Host Header:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_zone_boolean_change( $details, 'forward_host' ); ?></td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_cloudfront_fsd_configure_distribution w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
			<?php if ( ! empty( $details['distribution_id'] ) ) : ?>
				<input type="button"
					class="w3tc_cdn_cloudfront_fsd_configure_distribution_skip w3tc-button-save button"
					value="<?php esc_attr_e( 'Don\'t reconfigure, I know what I\'m doing', 'w3-total-cache' ); ?>" />
			<?php endif; ?>
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
