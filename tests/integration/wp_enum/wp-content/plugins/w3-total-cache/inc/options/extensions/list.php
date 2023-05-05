<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

/**
 *
 *
 * @var string $extension_status
 * @var int $page
 * @var array $extensions list of extensions for current $extension_status
 * @var array $extensions_all list of all extensions
 * @var array $extensions_active list of all active extensions
 * @var array $extensions_inactive list of all inactive extensions
 * @var array $extensions_core list of all core extensions
 */
?>
<ul class="subsubsub">
	<li class="all"><a href="?page=w3tc_extensions&extension_status=all"<?php echo 'all' === $extension_status ? ' class="current"' : ''; ?>>All <span class="count">(<?php echo esc_html( count( $extensions_all ) ); ?>)</span></a> |</li>
	<li class="active"><a href="?page=w3tc_extensions&extension_status=active"<?php echo 'active' === $extension_status ? ' class="current"' : ''; ?>>Active <span class="count">(<?php echo esc_html( count( $extensions_active ) ); ?>)</span></a> |</li>
	<li class="inactive"><a href="?page=w3tc_extensions&extension_status=inactive"<?php echo 'inactive' === $extension_status ? ' class="current"' : ''; ?>>Inactive <span class="count">(<?php echo esc_html( count( $extensions_inactive ) ); ?>)</span></a></li>
</ul>

<div class="tablenav top">

	<?php if ( ! $config->is_sealed( 'extensions.active' ) ) : ?>
		<div class="alignleft actions">
			<select name="action">
				<option value="-1" selected="selected"><?php esc_html_e( 'Bulk Actions', 'w3-total-cache' ); ?></option>
				<option value="activate-selected"><?php esc_html_e( 'Activate', 'w3-total-cache' ); ?></option>
				<option value="deactivate-selected"><?php esc_html_e( 'Deactivate', 'w3-total-cache' ); ?></option>
			</select>
			<input type="submit" name="" id="doaction" class="w3tc-button-save button action" value="<?php esc_attr_e( 'Apply' ); ?>">
		</div>
	<?php endif ?>

	<div class="tablenav-pages one-page">
		<span class="displaying-num">
			<?php
			echo esc_html(
				sprintf(
					translate_nooped_plural(
						// translators: 1 count of extensions.
						_n_noop(
							'%s extension',
							'%s extensions'
						),
						count( $extensions ),
						'w3-total-cache'
					),
					count( $extensions )
				)
			);
			?>
		</span>
	</div>
	<br class="clear">
</div>
<table class="wp-list-table widefat plugins w3tc_extensions" cellspacing="0">
	<thead>
		<tr>
			<th scope="col" id="cb" class="w3tc_extensions_manage_column_check"><label class="screen-reader-text" for="cb-select-all-1"><?php esc_html_e( 'Select All', 'w3-total-cache' ); ?></label><input id="cb-select-all-1" type="checkbox" class="w3tc_extensions_manage_input_checkall"></th><th scope="col" id="name" class="manage-column column-name" style=""><?php esc_html_e( 'Extension', 'w3-total-cache' ); ?></th><th scope="col" id="description" class="manage-column column-description" style=""><?php esc_html_e( 'Description', 'w3-total-cache' ); ?></th>
		</tr>
	</thead>
	<tfoot>
		<tr>
			<th scope="col" class="w3tc_extensions_manage_column_check"><label class="screen-reader-text" for="cb-select-all-2"><?php esc_html_e( 'Select All', 'w3-total-cache' ); ?></label><input id="cb-select-all-2" type="checkbox" class="w3tc_extensions_manage_input_checkall"></th><th scope="col" class="manage-column column-name" style=""><?php esc_html_e( 'Extension', 'w3-total-cache' ); ?></th><th scope="col" class="manage-column column-description" style=""><?php esc_html_e( 'Description', 'w3-total-cache' ); ?></th>
		</tr>
	</tfoot>
	<tbody id="the-list">
		<?php
		$cb_id = 0;
		foreach ( $extension_keys as $extension ) :
			$meta = $extensions[ $extension ];
			$meta = $this->default_meta( $meta );
			if ( ! $meta['public'] ) {
				continue;
			}

			$cb_id++;

			do_action( "w3tc_extension_before_row-{$extension}" );

			?>
			<tr id="<?php echo esc_attr( $extension ); ?>" class="<?php echo $config->is_extension_active( $extension ) ? 'active' : 'inactive'; ?>">
				<th scope="row" class="check-column">
					<label class="screen-reader-text" for="checkbox_<?php echo esc_attr( $cb_id ); ?>"><?php echo esc_html( sprintf( /* translators: 1 label for Extension select/deselect checkobox */ __( 'Select %1$s', 'w3-total-cache' ), $meta['name'] ) ); ?></label>
					<input type="checkbox" name="checked[]" value="<?php echo esc_attr( $extension ); ?>" id="checkbox_<?php echo esc_attr( $cb_id ); ?>" class="w3tc_extensions_input_active" <?php disabled( ! $meta['enabled'] ); ?>>
				</th>
				<td class="plugin-title">
					<strong><?php echo esc_html( $meta['name'] ); ?></strong>
					<div class="row-actions-visible">
						<?php
						if ( $config->is_extension_active( $extension ) ) :
							$extra_links = array();

							if ( isset( $meta['settings_exists'] ) && $meta['settings_exists'] ) {
								$extra_links[] = '<a class="edit" href="' .
									esc_attr( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions&extension=%s&action=view', $extension ) ) ) . '">' .
									esc_html__( 'Settings', 'w3-total-cache' ) . '</a>';
							}

							if ( isset( $meta['extra_links'] ) && is_Array( $meta['extra_links'] ) ) {
								$extra_links = array_merge( $extra_links, $meta['extra_links'] );
							}

							$extra_links = apply_filters( "w3tc_extension_plugin_links_{$extension}", $extra_links );
							$links       = implode( ' | ', $extra_links );

							if ( $links ) {
								echo wp_kses(
									$links,
									array(
										'a' => array(
											'href'  => array(),
											'class' => array(),
										),
									)
								);
							}
							?>

							<span class="0"></span>

							<?php if ( ! $config->is_sealed( 'extensions.active' ) ) : ?>
								<?php echo $links ? ' | ' : ''; ?>
								<span class="deactivate">
									<a href="<?php echo esc_url( wp_nonce_url( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions&action=deactivate&extension=%s&amp;extension_status=%s&amp;paged=%d', $extension, $extension_status, $page ) ), 'w3tc' ) ); ?>" title="<?php esc_attr_e( 'Deactivate this extension', 'w3-total-cache' ); ?> ">
										<?php esc_html_e( 'Deactivate' ); ?>
									</a>
								</span>
							<?php endif ?>
						<?php else : ?>
							<span class="activate">
								<?php if ( $meta['enabled'] ) : ?>
									<?php if ( ! $config->is_sealed( 'extensions.active' ) ) : ?>
										<a href="<?php echo esc_url( wp_nonce_url( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions&action=activate&extension=%s&amp;extension_status=%s&amp;paged=%d', $extension, $extension_status, $page ) ), 'w3tc' ) ); ?>" title="<?php esc_attr_e( 'Activate this extension', 'w3-total-cache' ); ?> ">
											<?php esc_html_e( 'Activate' ); ?>
										</a>
									<?php endif ?>
								<?php else : ?>
									<?php if ( ! empty( $meta['disabled_message'] ) ) : ?>
										<?php echo esc_html( $meta['disabled_message'] ); ?>
									<?php else : ?>
										<?php esc_html_e( 'Disabled: see Requirements', 'w3-total-cache' ); ?>
									<?php endif; ?>
								<?php endif; ?>
							</span>
						<?php endif ?>
					</div>
				</td>
				<td class="column-description desc">
					<div class="plugin-description">
						<p>
							<?php if ( isset( $meta['pro_feature'] ) && $meta['pro_feature'] ) : ?>
								<?php Util_Ui::pro_wrap_maybe_start(); ?>
								<?php Util_Ui::pro_wrap_description( $meta['pro_excerpt'], $meta['pro_description'], 'extension-' . $extension ); ?>
								<?php Util_Ui::pro_wrap_maybe_end( "extension_$extension" ); ?>
							<?php else : ?>
								<?php echo wp_kses( $meta['description'], Util_Ui::get_allowed_html_for_wp_kses_from_content( $meta['description'] ) ); ?>
							<?php endif ?>

							<?php if ( ! empty( $meta['requirements'] ) ) : ?>
								<p class="description">
									<?php
									echo esc_html(
										sprintf(
											// translators: 1 plugin requirements.
											__(
												'Requirements: %s',
												'w3-total-cache'
											),
											apply_filters( "w3tc_extension_requirements-{$extension}", $meta['requirements'] )
										)
									);
									?>
								</p>
								<?php do_action( "w3tc_extension_requirements-{$extension}" ); ?>
							<?php endif ?>
						</p>
					</div>

					<div class="<?php echo $config->is_extension_active( $extension ) ? 'active' : 'inactive'; ?> second plugin-version-author-uri">
						<?php
						echo esc_html(
							sprintf(
								// translators: 1 extension version number.
								__(
									'Version %s',
									'w3-total-cache'
								),
								$meta['version']
							)
						);
						?>
						|
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 HTML a tag to extension author page.
								__(
									'By %s',
									'w3-total-cache'
								),
								'<a href="' . esc_url( $meta['author_uri'] ) . '" title="' . __( 'Visit author homepage', 'w3-total-cache' ) . '">' . esc_html( $meta['author'] ) . '</a>'
							),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
							)
						);
						?>
						|
						<a href="<?php echo esc_url( $meta['extension_uri'] ); ?>"
							title="<?php esc_attr_e( 'Visit extension site', 'w3-total-cache' ); ?>">
							<?php esc_html_e( 'Visit extension site', 'w3-total-cache' ); ?></a>
					</div>
				</td>
			</tr>
			<?php do_action( 'w3tc_extension_after_row', $extension ); ?>
			<?php do_action( "w3tc_extension_after_row-{$extension}" ); ?>
		<?php endforeach ?>
	</tbody>
</table>
<div class="tablenav bottom">

	<?php if ( ! $config->is_sealed( 'extensions.active' ) ) : ?>
		<div class="alignleft actions">
			<select name="action2">
				<option value="-1" selected="selected"><?php esc_html_e( 'Bulk Actions', 'w3-total-cache' ); ?></option>
				<option value="activate-selected"><?php esc_html_e( 'Activate', 'w3-total-cache' ); ?></option>
				<option value="deactivate-selected"><?php esc_html_e( 'Deactivate', 'w3-total-cache' ); ?></option>
			</select>
			<input type="submit" name="" id="doaction" class="w3tc-button-save button action" value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>">
		</div>
	<?php endif ?>

	<div class="tablenav-pages one-page">
		<span class="displaying-num">
			<?php
			echo esc_html(
				sprintf(
					translate_nooped_plural(
						// translators: 1 count of extensions.
						_n_noop(
							'%s extension',
							'%s extensions'
						),
						count( $extensions ),
						'w3-total-cache'
					),
					count( $extensions )
				)
			);
			?>
		</span>
	</div>
	<br class="clear">
</div>

<?php if ( is_network_admin() ) : ?>
	<?php Util_Ui::button_config_save( 'extensions' ); ?>
<?php endif ?>
