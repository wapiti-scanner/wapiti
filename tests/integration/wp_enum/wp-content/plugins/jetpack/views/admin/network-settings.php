<?php
/**
 * Jetpack Network Settings view template.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\IP\Utils as IP_Utils;

if ( isset( $_GET['updated'] ) && 'true' === $_GET['updated'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	?>
	<div class="updated"><p><?php esc_html_e( 'Jetpack Network Settings Updated!', 'jetpack' ); ?></p></div>
<?php endif; ?>

<?php
if ( isset( $_GET['error'] ) && 'jetpack_protect_whitelist' === $_GET['error'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	?>
	<div class="error"><p><?php esc_html_e( 'One of your IP addresses was not valid.', 'jetpack' ); ?></p></div>
<?php endif; ?>

<div class="wrap">
	<h2><?php esc_html_e( 'Network Settings', 'jetpack' ); ?></h2>
	<form action="edit.php?action=jetpack-network-settings" method="POST">
		<h3><?php echo esc_html_x( 'Global', 'Affects all sites in a Multisite network.', 'jetpack' ); ?></h3>
		<p><?php esc_html_e( 'These settings affect all sites on the network.', 'jetpack' ); ?></p>
		<?php wp_nonce_field( 'jetpack-network-settings' ); ?>
		<table class="form-table">
			<tr valign="top">
				<th scope="row"><label for="sub-site-override"><?php esc_html_e( 'Sub-site override', 'jetpack' ); ?></label></th>
				<td>
					<input type="checkbox" name="sub-site-connection-override" id="sub-site-override" value="1" <?php checked( $data['options']['sub-site-connection-override'] ); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable ?> />
					<label for="sub-site-override"><?php esc_html_e( 'Allow individual site administrators to manage their own connections (connect and disconnect) to WordPress.com', 'jetpack' ); ?></label>
				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="sub-site-override"><?php esc_html_e( 'Protect IP allow list', 'jetpack' ); ?></label></th>
				<td>
					<p><strong>
					<?php
					$current_ip = IP_Utils::get_ip();
					if ( ! empty( $current_ip ) ) {
						printf(
							/* Translators: placeholder is an IP address. */
							esc_html__( 'Your current IP: %1$s', 'jetpack' ),
							esc_html( $current_ip )
						);
					}
					?>
					</strong></p>
					<?php
					echo '<textarea name="global-allow-list" style="width: 100%;" rows="8">'; // echo to avoid tabs displayed in textarea. See https://github.com/Automattic/jetpack/pull/21151/files#r713922521.

					foreach ( $data['jetpack_protect_whitelist']['global'] as $ip ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
						echo esc_html( $ip ) . "\n";
					}
					?>
					</textarea> <br />
					<label for="global-allow-list">
						<?php esc_html_e( 'IPv4 and IPv6 are acceptable. Enter multiple IPs on separate lines.', 'jetpack' ); ?>
						<br />
						<?php esc_html_e( 'To specify a range, enter the low value and high value separated by a dash. Example: 12.12.12.1-12.12.12.100', 'jetpack' ); ?>
					</label>
				</td>
			</tr>
		</table>
		<?php submit_button(); ?>

	</form>
</div>
