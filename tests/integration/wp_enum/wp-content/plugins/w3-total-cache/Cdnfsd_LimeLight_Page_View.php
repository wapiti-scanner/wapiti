<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$key        = $config->get_string( 'cdnfsd.limelight.api_key' );
$authorized = ! empty( $key );

?>
<form id="cdn_form" action="admin.php?page=w3tc_cdn" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Configuration: Full-Site Delivery', 'w3-total-cache' ), '', 'configuration' ); ?>
		<table class="form-table">
			<tr>
				<th style="width: 300px;">
					<label>
						<?php esc_html_e( 'Specify account credentials:', 'w3-total-cache' ); ?>
					</label>
				</th>
				<td>
					<?php if ( $authorized ) : ?>
						<input class="w3tc_cdnfsd_limelight_authorize button-primary"
							type="button" value="<?php esc_attr_e( 'Reauthorize', 'w3-total-cache' ); ?>" />
					<?php else : ?>
						<input class="w3tc_cdnfsd_limelight_authorize button-primary"
							type="button" value="<?php esc_attr_e( 'Authorize', 'w3-total-cache' ); ?>" />
					<?php endif ?>
				</td>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
