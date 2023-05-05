<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_cdn_stackpath2_form" method="post">
	<?php Util_Ui::hidden( '', 'api_config', $details['api_config'] ); ?>

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Select site to use', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td><?php esc_html_e( 'Site:', 'w3-total-cache' ); ?></td>
				<td>
					<?php
					if ( count( $details['sites'] ) > 15 ) {
						echo '<div style="width: 100%; height: 300px; overflow-y: scroll">';
					}
					?>

					<?php foreach ( $details['sites'] as $i ) : ?>
						<label>
							<input name="site_id" type="radio" class="w3tc-ignore-change"
								value="<?php echo esc_attr( $i['id'] ); ?>" />
							<?php echo esc_html( $i['label'] ); ?>
						</label><br />
					<?php endforeach ?>

					<label>
						<input name="site_id" type="radio" class="w3tc-ignore-change" value="" />
						<?php echo esc_html__( 'Add new site: ', 'w3-total-cache' ) . esc_html( $details['new_hostname'] ); ?>
					</label>

					<?php
					if ( count( $details['sites'] ) > 15 ) {
						echo '</div>';
					}
					?>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath2_configure_site w3tc-button-save button-primary"
				value="<?php esc_html_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
