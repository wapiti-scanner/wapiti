<?php
/**
 * A list of form revisions in the Form Builder Revisions panel.
 *
 * @since 1.7.3
 *
 * @var string $active_class        Active item class.
 * @var string $current_version_url The URL to load the current form version.
 * @var string $author_id           Current form author ID.
 * @var array  $revisions           A list of all form revisions.
 * @var string $show_avatars        Whether the site settings for showing avatars is enabled.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class='wpforms-revisions-content'>
	<div class="wpforms-revision-current-version<?php echo esc_attr( $active_class ); ?>">
		<a href="<?php echo esc_url( $current_version_url ); ?>">
			<?php if ( $show_avatars ) : ?>
				<div class="wpforms-revision-gravatar">
					<?php echo get_avatar( $author_id, 40 ); ?>
				</div>
			<?php endif; ?>

			<div class='wpforms-revision-details'>
				<p class='wpforms-revision-created'>
					<strong><?php esc_html_e( 'Current Version', 'wpforms-lite' ); ?></strong>
				</p>

				<p class='wpforms-revision-author'>
					<?php
					$display_name = get_the_author_meta( 'display_name', $author_id );

					printf( /* translators: %s - form revision author name. */
						esc_html__( 'by %s', 'wpforms-lite' ),
						! empty( $display_name ) ? esc_html( $display_name ) : esc_html__( 'Unknown user', 'wpforms-lite' )
					);
					?>
				</p>
			</div>
		</a>
	</div>

	<ul class="wpforms-revisions-list">
		<?php foreach ( $revisions as $revision ) : ?>

			<li class="wpforms-revision<?php echo esc_attr( $revision['active_class'] ); ?>">
				<a href="<?php echo esc_url( $revision['url'] ); ?>">
					<?php if ( $show_avatars ) : ?>
						<div class="wpforms-revision-gravatar">
							<?php echo get_avatar( $revision['author_id'], 40 ); ?>
						</div>
					<?php endif; ?>

					<div class='wpforms-revision-details'>
						<p class='wpforms-revision-created'>
							<strong><?php echo esc_html( $revision['time_diff'] ); ?></strong> (<?php echo esc_html( $revision['date_time'] ); ?>)
						</p>

						<p class='wpforms-revision-author'>
							<?php
							$display_name = get_the_author_meta( 'display_name', $revision['author_id'] );

							printf( /* translators: %s - form revision author name. */
								esc_html__( 'by %s', 'wpforms-lite' ),
								! empty( $display_name ) ? esc_html( $display_name ) : esc_html__( 'Unknown user', 'wpforms-lite' )
							);
							?>
						</p>
					</div>
				</a>
			</li>

		<?php endforeach; ?>
	</ul>
</div>
