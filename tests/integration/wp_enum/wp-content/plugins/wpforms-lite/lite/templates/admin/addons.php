<?php
/**
 * Admin > Addons page template.
 *
 * @since 1.6.7
 *
 * @var string $upgrade_link_base Upgrade link base.
 * @var array  $addons            Addons data.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id="wpforms-admin-addons" class="wrap wpforms-admin-wrap">
	<h1 class="page-title">
		<?php esc_html_e( 'WPForms Addons', 'wpforms-lite' ); ?>
		<input type="search" placeholder="<?php esc_html_e( 'Search Addons', 'wpforms-lite' ); ?>" id="wpforms-admin-addons-search">
	</h1>
	<div class="wpforms-admin-content">
		<div id="wpforms-admin-addons-list">
			<div class="list">
				<?php
				foreach ( $addons as $addon ) :
					$addon['icon']    = ! empty( $addon['icon'] ) ? $addon['icon'] : '';
					$addon['title']   = ! empty( $addon['title'] ) ? $addon['title'] : __( 'Unknown Addon', 'wpforms-lite' );
					$addon['excerpt'] = ! empty( $addon['excerpt'] ) ? $addon['excerpt'] : '';
					$upgrade_link     = add_query_arg(
						[
							'utm_content' => $addon['title'],
						],
						$upgrade_link_base
					);

					if ( $addon['slug'] === 'wpforms-stripe' ) {
						$addon['recommended'] = true;
					}
				?>
					<div class="addon-container">
						<div class="addon-item">
							<div class="details wpforms-clear">
								<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/' . $addon['icon'] ); ?>" alt="<?php echo esc_attr( $addon['title'] ); ?> <?php esc_attr_e( 'logo', 'wpforms-lite' ); ?>">
								<h5 class="addon-name">
									<?php
									printf(
										'<a href="%1$s" title="%2$s" target="_blank" rel="noopener noreferrer" class="addon-link">%3$s</a>',
										esc_url( $upgrade_link ),
										esc_attr__( 'Learn more', 'wpforms-lite' ),
										esc_html( $addon['title'] )
									);
									?>
									<?php if ( ! empty( $addon['recommended'] ) ) : ?>
										<span class="wpforms-addon-recommended">
											<i class="fa fa-star" aria-hidden="true"></i>
											<?php esc_html_e( 'Recommended', 'wpforms-lite' ); ?>
										</span>
									<?php endif; ?>
								</h5>
								<p class="addon-desc"><?php echo esc_html( $addon['excerpt'] ); ?></p>
							</div>
							<div class="actions wpforms-clear">
								<div class="upgrade-button">
									<a href="<?php echo esc_url( $upgrade_link ); ?>" target="_blank" rel="noopener noreferrer" class="wpforms-btn wpforms-btn-orange wpforms-upgrade-modal">
										<?php esc_html_e( 'Upgrade Now', 'wpforms-lite' ); ?>
									</a>
								</div>
							</div>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
	</div>
</div>
