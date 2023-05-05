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
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Select distribution to use', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>Distribution:</td>
				<td>
					<?php
					if ( count( $details['distributions'] ) > 15 ) {
						echo '<div style="width: 100%; height: 300px; overflow-y: scroll">';
					}
					?>

					<?php foreach ( $details['distributions'] as $distribution ) : ?>
						<label>
							<input name="distribution_id" type="radio" class="w3tc-ignore-change"
								value="<?php echo esc_attr( $distribution['Id'] ); ?>" />
							<?php echo esc_html( $distribution['Comment'] ); ?>
							(origin <?php echo esc_html( $distribution['Origin_DomainName'] ); ?>)
						</label><br />
					<?php endforeach; ?>

					<label>
						<input name="distribution_id" type="radio" class="w3tc-ignore-change" value="" />
						Add new distribution
						<input name="comment_new" type="text" class="w3tc-ignore-change" />
					</label>

					<?php
					if ( count( $details['distributions'] ) > 15 ) {
						echo '</div>';
					}
					?>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_cloudfront_fsd_view_distribution w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
