<?php
/**
 * Email Summary body template.
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/summary-body.php.
 *
 * @since 1.5.4
 *
 * @var array $entries
 * @var array $info_block
 */

use WPForms\Integrations\LiteConnect\LiteConnect;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<table class="summary-container">
	<tbody>
	<tr>
		<td>
			<h6 class="greeting"><?php esc_html_e( 'Hi there!', 'wpforms-lite' ); ?></h6>
			<?php if ( wpforms()->is_pro() ) : ?>
				<p class="large"><?php esc_html_e( 'Let’s see how your forms performed in the past week.', 'wpforms-lite' ); ?></p>
			<?php else : ?>
				<p class="large"><?php esc_html_e( 'Let’s see how your forms performed.', 'wpforms-lite' ); ?></p>
				<p class="lite-disclaimer">
					<?php esc_html_e( 'Below is the total number of submissions for each form. However, form entries are not stored by WPForms Lite.', 'wpforms-lite' ); ?>
				</p>

				<?php if ( LiteConnect::is_enabled() ) : ?>
					<p class="lite-disclaimer">
						<strong><?php esc_html_e( 'We’ve got you covered!', 'wpforms-lite' ); ?></strong><br/>
						<?php
						printf(
							wp_kses( /* translators: %s - WPForms.com Upgrade page URL. */
								__( 'Your entries are being backed up securely in the cloud. When you’re ready to manage your entries inside WordPress, just <a href="%s" target="_blank" rel="noopener noreferrer">upgrade to Pro</a> and we’ll automatically import them in seconds!', 'wpforms-lite' ),
								[
									'a' => [
										'href'   => [],
										'rel'    => [],
										'target' => [],
									],
								]
							),
							'https://wpforms.com/lite-upgrade/?utm_source=WordPress&utm_medium=Weekly%20Summary%20Email&utm_campaign=liteplugin&utm_content=Upgrade&utm_locale=' . wpforms_sanitize_key( get_locale() )
						);
						?>
					</p>
					<p class="lite-disclaimer">
						<?php
							printf(
								'<a href="%1$s" target="_blank" rel="noopener noreferrer">%2$s</a>',
								'https://wpforms.com/lite-upgrade/?utm_source=WordPress&utm_medium=Weekly%20Summary%20Email&utm_campaign=liteplugin&utm_content=Upgrade&utm_locale=' . wpforms_sanitize_key( get_locale() ),
								esc_html__( 'Check out what else you’ll get with your Pro license.', 'wpforms-lite' )
							);
						?>
					</p>
				<?php else : ?>
						<p class="lite-disclaimer">
							<strong><?php esc_html_e( 'Note: Entry backups are not enabled.', 'wpforms-lite' ); ?></strong><br/>
							<?php esc_html_e( 'We recommend that you enable entry backups to guard against lost entries.', 'wpforms-lite' ); ?>
						</p>
						<p class="lite-disclaimer">
							<?php
							printf(
								wp_kses( /* translators: %s - WPForms.com Documentation page URL. */
									__( 'Backups are completely free, 100%% secure, and you can turn them on in a few clicks! <a href="%s" target="_blank" rel="noopener noreferrer">Enable entry backups now.</a>', 'wpforms-lite' ),
									[
										'a' => [
											'href'   => [],
											'rel'    => [],
											'target' => [],
										],
									]
								),
								'https://wpforms.com/docs/how-to-use-lite-connect-for-wpforms/#backup-with-lite-connect/?utm_source=WordPress&utm_medium=Weekly%20Summary%20Email&utm_campaign=liteplugin&utm_content=Documentation'
							);
							?>
						</p>
						<p class="lite-disclaimer">
							<?php
							printf(
								wp_kses( /* translators: %s - WPForms.com Upgrade page URL. */
									__( 'When you’re ready to manage your entries inside WordPress, <a href="%s" target="_blank" rel="noopener noreferrer">upgrade to Pro</a> to import your entries.', 'wpforms-lite' ),
									[
										'a' => [
											'href'   => [],
											'rel'    => [],
											'target' => [],
										],
									]
								),
								'https://wpforms.com/lite-upgrade/?utm_source=WordPress&utm_medium=Weekly%20Summary%20Email&utm_campaign=liteplugin&utm_content=Upgrade&utm_locale=' . wpforms_sanitize_key( get_locale() )
							);
							?>
						</p>
				<?php endif; ?>

			<?php endif; ?>
			<table class="email-summaries">
				<thead>
				<tr>
					<th><?php esc_html_e( 'Form', 'wpforms-lite' ); ?></th>
					<th class="entries-column text-center"><?php esc_html_e( 'Entries', 'wpforms-lite' ); ?></th>
				</tr>
				</thead>
				<tbody>

				<?php foreach ( $entries as $row ) : ?>
					<tr>
						<td class="text-large"><?php echo isset( $row['title'] ) ? esc_html( $row['title'] ) : ''; ?></td>
						<td class="entry-count text-large">
							<?php if ( empty( $row['edit_url'] ) ) : ?>
								<span>
									<?php echo isset( $row['count'] ) ? absint( $row['count'] ) : ''; ?>
								</span>
							<?php else : ?>
								<a href="<?php echo esc_url( $row['edit_url'] ); ?>">
									<?php echo isset( $row['count'] ) ? absint( $row['count'] ) : ''; ?>
								</a>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>

				<?php if ( empty( $entries ) ) : ?>
					<tr>
						<td class="text-center" colspan="2"><?php esc_html_e( 'It appears you do not have any form entries yet.', 'wpforms-lite' ); ?></td>
					</tr>
				<?php endif; ?>

				</tbody>
			</table>


			<?php if ( ! empty( $info_block ) ) : ?>
				<table class="summary-info-table">
					<?php if ( ! empty( $info_block['title'] ) || ! empty( $info_block['content'] ) ) : ?>
						<tr>
							<td class="summary-info-content">
								<table>
									<?php if ( ! empty( $info_block['title'] ) ) : ?>
										<tr>
											<td class="text-center">
												<h6><?php echo esc_html( $info_block['title'] ); ?></h6>
											</td>
										</tr>
									<?php endif; ?>
									<?php if ( ! empty( $info_block['content'] ) ) : ?>
										<tr>
											<td class="text-center"><?php echo wp_kses_post( $info_block['content'] ); ?></td>
										</tr>
									<?php endif; ?>
								</table>
							</td>
						</tr>
					<?php endif; ?>

					<?php if ( ! empty( $info_block['url'] ) && ! empty( $info_block['button'] ) ) : ?>
						<tr>
							<td class="summary-info-content button-container">
								<center>
									<table class="button rounded-button">
										<tr>
											<td>
												<table>
													<tr>
														<td>
															<a href="<?php echo esc_url( $info_block['url'] ); ?>" rel="noopener noreferrer" target="_blank">
																<?php echo esc_html( $info_block['button'] ); ?>
															</a>
														</td>
													</tr>
												</table>
											</td>
										</tr>
									</table>
								</center>
							</td>
						</tr>
					<?php endif; ?>

				</table>
			<?php endif; ?>
		</td>
	</tr>
	</tbody>
</table>
