<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<script type="text/javascript">/*<![CDATA[*/
	var minify_templates = {};
	<?php foreach ( $templates as $theme_key => $theme_templates ) : ?>
		minify_templates['<?php echo esc_html( addslashes( $theme_key ) ); ?>'] = {};
		<?php foreach ( $theme_templates as $theme_template_key => $theme_template_name ) : ?>
			minify_templates['<?php echo esc_html( addslashes( $theme_key ) ); ?>']['<?php echo esc_html( addslashes( $theme_template_key ) ); ?>'] = '<?php echo esc_html( addslashes( $theme_template_name ) ); ?>';
		<?php endforeach; ?>
	<?php endforeach; ?>
/*]]>*/</script>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 minify engine name, HTML span tag indicating engine enabled/disabled.
				__(
					'Minify via %1$s is currently %2$s.',
					'w3-total-cache'
				),
				Cache::engine_name( $this->_config->get_string( 'minify.engine' ) ),
				'<span class="w3tc-' . ( $minify_enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>'
			),
			array(
				'span' => array(
					'class' => array(),
				),
			)
		);
		?>
	</p>
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 HTML submit button to rebuild minify cache.
				__(
					'To rebuild the minify cache use the %1$s operation.',
					'w3-total-cache'
				),
				Util_Ui::nonce_field( 'w3tc' ) . '<input type="submit" name="w3tc_flush_minify" value="' . esc_attr__( 'empty cache', 'w3-total-cache' ) . '"' . disabled( $minify_enabled, false, false ) . ' class="button" />'
			),
			array(
				'input' => array(
					'type'     => array(),
					'name'     => array(),
					'value'    => array(),
					'disabled' => array(),
					'class'    => array(),
				),
			)
		);
		?>
		<?php if ( ! $auto ) : ?>
			<?php esc_html_e( 'Get minify hints using the', 'w3-total-cache' ); ?>
			<input type="button" class="button button-minify-recommendations {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" value="<?php esc_attr_e( 'help', 'w3-total-cache' ); ?>" />
			<?php esc_html_e( 'wizard.', 'w3-total-cache' ); ?>
		<?php endif; ?>
		<?php
		echo wp_kses(
			sprintf(
				// translators: %1 HTML input submit.
				__(
					'%1$s to make existing file modifications visible to visitors with a primed cache.',
					'w3-total-cache'
				),
				'<input type="submit" name="w3tc_flush_browser_cache" value="' . esc_attr__( 'Update media query string', 'w3-total-cache' ) . '"' . disabled( ! ( $browsercache_enabled && $browsercache_update_media_qs ), true, false ) . ' class="button" />'
			),
			array(
				'input' => array(
					'type'     => array(),
					'name'     => array(),
					'value'    => array(),
					'disabled' => array(),
					'class'    => array(),
				),
			)
		);
		?>
	</p>
</form>

<form id="minify_form" action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '', 'general' ); ?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php
					$this->checkbox(
						'minify.rewrite',
						$minify_rewrite_disabled,
						'',
						true,
						( ! Util_Rule::can_check_rules() ? false : null )
					);
					?>
					<?php Util_Ui::e_config_label( 'minify.rewrite' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'If disabled, %1$sCSS%2$s and %3$sJS%4$s embeddings will use GET variables instead of "fancy" links.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'minify.reject.logged' ); ?> <?php Util_Ui::e_config_label( 'minify.reject.logged' ); ?></label>
					<p class="description"><?php esc_html_e( 'Authenticated users will not receive minified pages if this option is enabled.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<?php
			Util_Ui::config_item(
				array(
					'key'              => 'minify.error.notification',
					'control'          => 'selectbox',
					'selectbox_values' => array(
						''            => esc_html__( 'Disabled', 'w3-total-cache' ),
						'admin'       => esc_html__( 'Admin Notification', 'w3-total-cache' ),
						'email'       => esc_html__( 'Email Notification', 'w3-total-cache' ),
						'admin,email' => esc_html__( 'Both Admin &amp; Email Notification', 'w3-total-cache' ),
					),
					'description'      => esc_html__( 'Notify when minify cache creation errors occur.', 'w3-total-cache' ),
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'minify_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header(
			wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1$sHTML%2$s &amp; %3$sXML%4$s',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'eXtensible Markup Language', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'',
			'html_xml'
		);
		?>
		<table class="form-table">
			<tr>
				<th>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sHTML%2$s minify settings:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</th>
				<td>
					<?php $this->checkbox( 'minify.html.enable' ); ?> <?php Util_Ui::e_config_label( 'minify.html.enable' ); ?></label><br />
					<?php $this->checkbox( 'minify.html.inline.css', false, 'html_' ); ?> <?php Util_Ui::e_config_label( 'minify.html.inline.css' ); ?></label><br />
					<?php $this->checkbox( 'minify.html.inline.js', false, 'html_' ); ?> <?php Util_Ui::e_config_label( 'minify.html.inline.js' ); ?></label><br />
					<?php $this->checkbox( 'minify.html.reject.feed', false, 'html_' ); ?> <?php Util_Ui::e_config_label( 'minify.html.reject.feed' ); ?></label><br />
					<?php
					$html_engine_file = '';

					switch ( $html_engine ) {
						case 'html':
						case 'htmltidy':
							$html_engine_file = W3TC_INC_DIR . '/options/minify/' . $html_engine . '.php';
							break;
					}

					if ( file_exists( $html_engine_file ) ) {
						include $html_engine_file;
					}
					?>
				</td>
			</tr>
			<tr>
				<th><label for="minify_html_comments_ignore"><?php Util_Ui::e_config_label( 'minify.html.comments.ignore' ); ?></label></th>
				<td>
					<textarea id="minify_html_comments_ignore"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?>
						name="minify__html__comments__ignore" class="html_enabled" cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'minify.html.comments.ignore' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Do not remove comments that contain these terms.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<?php
			$html_engine_file2 = '';

			switch ( $html_engine_file2 ) {
				case 'html':
				case 'htmltidy':
					$html_engine_file = W3TC_INC_DIR . '/options/minify/' . $html_engine . '2.php';
					break;
			}

			if ( file_exists( $html_engine_file2 ) ) {
				include $html_engine_file2;
			}
			?>
		</table>

		<?php Util_Ui::button_config_save( 'minify_html_xml' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'%1$sJS%2$s',
					'w3-total-cache'
				),
				'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			'',
			'js'
		);
		?>
		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'minify.js.enable',
					'label'          => sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'%1$sJS%2$s minify settings:',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
						'</acronym>'
					),
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				)
			);
			?>
			<?php
			if ( $auto ) :
				Util_Ui::config_item(
					array(
						'key'              => 'minify.js.method',
						'label'            => esc_html__( 'Minify method:', 'w3-total-cache' ),
						'control'          => 'selectbox',
						'selectbox_values' => array(
							'both'    => array(
								'label' => esc_html__( 'Combine & Minify', 'w3-total-cache' ),
							),
							'minify'  => array(
								'label' => esc_html__( 'Minify only', 'w3-total-cache' ),
							),
							'combine' => array(
								'label' => esc_html__( 'Combine only', 'w3-total-cache' ),
							),
						),
					)
				);
			endif;
			?>
			<tr>
				<th><?php esc_html_e( 'Minify engine settings:', 'w3-total-cache' ); ?></th>
				<td>
					<fieldset><legend><?php esc_html_e( 'Operations in areas:', 'w3-total-cache' ); ?></legend>
						<table id="minify_table">
							<tr>
								<td></td>
								<td></td>
								<td class="options"><?php Util_Ui::e_config_label( 'minify.js.header.embed_type' ); ?></td>
							</tr>
							<tr>
								<td class="placement">
									<?php
									echo wp_kses(
										sprintf(
											// translators: 1 opening HTML span tag, 2 closing HTML span tag.
											__(
												'Before %1$s&lt;/head&gt;%2$s',
												'w3-total-cache'
											),
											'<span class="html-tag">',
											'</span>'
										),
										array(
											'span' => array(
												'class' => array(),
											),
										)
									);
									?>
								</td>
								<td class="options">
									<?php if ( ! $auto ) : ?>
										<?php $this->radio( 'minify.js.combine.header', false, false, 'js_' ); ?> <?php esc_html_e( 'Minify', 'w3-total-cache' ); ?> </label> <?php $this->radio( 'minify.js.combine.header', true, false, 'js_' ); ?> <?php Util_Ui::e_config_label( 'minify.js.combine.header' ); ?></label>
									<?php endif; ?>
								</td>
								<td class="options">
									<select id="js_use_type_header" name="minify__js__header__embed_type" class="js_enabled">
										<option value="blocking" <?php selected( 'blocking', $this->_config->get_string( 'minify.js.header.embed_type' ) ); ?>><?php esc_html_e( 'Default (blocking)', 'w3-total-cache' ); ?></option>
										<option value="nb-js" <?php selected( 'nb-js', $this->_config->get_string( 'minify.js.header.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using JS', 'w3-total-cache' ); ?></option>
										<option value="nb-async" <?php selected( 'nb-async', $this->_config->get_string( 'minify.js.header.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "async"', 'w3-total-cache' ); ?></option>
										<option value="nb-defer" <?php selected( 'nb-defer', $this->_config->get_string( 'minify.js.header.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "defer"', 'w3-total-cache' ); ?></option>
										<?php if ( ! $auto ) : ?>
											<option value="extsrc" <?php selected( 'extsrc', $this->_config->get_string( 'minify.js.header.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "extsrc"', 'w3-total-cache' ); ?></option>
											<option value="asyncsrc" <?php selected( 'asyncsrc', $this->_config->get_string( 'minify.js.header.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "asyncsrc"', 'w3-total-cache' ); ?></option>
										<?php endif; ?>
									</select>
								</td>
							<tr>
								<td class="placement"><?php Util_Ui::e_config_label( 'minify.js.body.embed_type' ); ?></td>
								<td class="options">
									<?php if ( ! $auto ) : ?>
										<?php $this->radio( 'minify.js.combine.body', false, $auto, 'js_' ); ?> <?php esc_html_e( 'Minify', 'w3-total-cache' ); ?> </label> <?php $this->radio( 'minify.js.combine.body', true ); ?> <?php Util_Ui::e_config_label( 'minify.js.combine.body' ); ?></label>
									<?php endif; ?>
								</td>
								<td class="options">
									<select id="js_use_type_body" name="minify__js__body__embed_type" class="js_enabled">
										<option value="blocking" <?php selected( 'blocking', $this->_config->get_string( 'minify.js.body.embed_type' ) ); ?>><?php esc_html_e( 'Default (blocking)', 'w3-total-cache' ); ?></option>
										<option value="nb-js" <?php selected( 'nb-js', $this->_config->get_string( 'minify.js.body.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using JS', 'w3-total-cache' ); ?></option>
										<option value="nb-async" <?php selected( 'nb-async', $this->_config->get_string( 'minify.js.body.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "async"', 'w3-total-cache' ); ?></option>
										<option value="nb-defer" <?php selected( 'nb-defer', $this->_config->get_string( 'minify.js.body.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "defer"', 'w3-total-cache' ); ?></option>
										<?php if ( ! $auto ) : ?>
											<option value="extsrc" <?php selected( 'extsrc', $this->_config->get_string( 'minify.js.body.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "extsrc"', 'w3-total-cache' ); ?></option>
											<option value="asyncsrc" <?php selected( 'asyncsrc', $this->_config->get_string( 'minify.js.body.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "asyncsrc"', 'w3-total-cache' ); ?></option>
										<?php endif; ?>
									</select>
								</td>
							</tr>
							<?php if ( ! $auto ) : ?>
								<tr>
									<td class="placement"><?php Util_Ui::e_config_label( 'minify.js.footer.embed_type' ); ?></td>
									<td class="options">
										<?php $this->radio( 'minify.js.combine.footer', false, $auto, 'js_' ); ?> <?php esc_html_e( 'Minify', 'w3-total-cache' ); ?> </label> <?php $this->radio( 'minify.js.combine.footer', true ); ?> <?php Util_Ui::e_config_label( 'minify.js.combine.footer' ); ?></label>
									</td>
									<td class="options">
										<select id="js_use_type_footer" name="minify__js__footer__embed_type" class="js_enabled">
											<option value="blocking" <?php selected( 'blocking', $this->_config->get_string( 'minify.js.footer.embed_type' ) ); ?>><?php esc_html_e( 'Default (blocking)', 'w3-total-cache' ); ?></option>
											<option value="nb-js" <?php selected( 'nb-js', $this->_config->get_string( 'minify.js.footer.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using JS', 'w3-total-cache' ); ?></option>
											<option value="nb-async" <?php selected( 'nb-async', $this->_config->get_string( 'minify.js.footer.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "async"', 'w3-total-cache' ); ?></option>
											<option value="nb-defer" <?php selected( 'nb-defer', $this->_config->get_string( 'minify.js.footer.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "defer"', 'w3-total-cache' ); ?></option>
											<option value="extsrc" <?php selected( 'extsrc', $this->_config->get_string( 'minify.js.footer.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "extsrc"', 'w3-total-cache' ); ?></option>
											<option value="asyncsrc" <?php selected( 'asyncsrc', $this->_config->get_string( 'minify.js.footer.embed_type' ) ); ?>><?php esc_html_e( 'Non-blocking using "asyncsrc"', 'w3-total-cache' ); ?></option>
										</select>
									</td>
								</tr>
							<?php endif; ?>
						</table>
					</fieldset>

					<?php
					$js_engine_file = '';

					switch ( $js_engine ) {
						case 'js':
						case 'yuijs':
						case 'ccjs':
							$js_engine_file = W3TC_INC_DIR . '/options/minify/' . $js_engine . '.php';
							break;
					}

					if ( file_exists( $js_engine_file ) ) {
						include $js_engine_file;
					}
					?>
				</td>
			</tr>
			<?php
			$js_engine_file2 = '';

			switch ( $js_engine ) {
				case 'js':
				case 'yuijs':
				case 'ccjs':
				case 'googleccjs':
					$js_engine_file2 = W3TC_INC_DIR . '/options/minify/' . $js_engine . '2.php';
					break;
			}

			if ( file_exists( $js_engine_file2 ) ) {
				include $js_engine_file2;
			}
			?>
			<?php if ( ! $auto ) : ?>
				<tr>
					<th>
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'%1$sJS%2$s file management:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</th>
					<td>
						<p>
							<label>
								<?php esc_html_e( 'Theme:', 'w3-total-cache' ); ?>
								<select id="js_themes" class="js_enabled" name="js_theme"
									<?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
									<?php foreach ( $themes as $theme_key => $theme_name ) : ?>
										<option value="<?php echo esc_attr( $theme_key ); ?>"<?php selected( $theme_key, $js_theme ); ?>>
											<?php
											echo esc_html( $theme_name );
											if ( $theme_key === $js_theme ) {
												echo ' (active)';
											}
											?>
										</option>
									<?php endforeach; ?>
								</select>
							</label>
							<p class="description"><?php esc_html_e( 'Files are minified by template. First select the theme to manage, then add scripts used in all templates to the "All Templates" group. Use the menu above to manage scripts unique to a specific template. If necessary drag &amp; drop to resolve dependency issues (due to incorrect order).', 'w3-total-cache' ); ?></p>
						</p>
						<ul id="js_files" class="minify-files">
						<?php
						foreach ( $js_groups as $js_theme => $js_templates ) :
							if ( isset( $templates[ $js_theme ] ) ) :
								$index = 0;
								foreach ( $js_templates as $js_template => $js_locations ) :
									foreach ( (array) $js_locations as $js_location => $js_config ) :
										if ( ! empty( $js_config['files'] ) ) :
											foreach ( (array) $js_config['files'] as $js_file ) :
												$index++;
												?>
												<li>
													<table>
														<tr>
															<th>&nbsp;</th>
															<th><?php esc_html_e( 'File URI:', 'w3-total-cache' ); ?></th>
															<th><?php esc_html_e( 'Template:', 'w3-total-cache' ); ?></th>
															<th colspan="3"><?php esc_html_e( 'Embed Location:', 'w3-total-cache' ); ?></th>
														</tr>
														<tr>
															<td><?php echo esc_html( $index ); ?>.</td>
															<td>
																<input class="js_enabled" type="text" <?php Util_Ui::sealing_disabled( 'minify.' ); ?>
																	name="js_files[<?php echo esc_attr( $js_theme ); ?>][<?php echo esc_attr( $js_template ); ?>][<?php echo esc_attr( $js_location ); ?>][]"
																	value="<?php echo esc_attr( $js_file );  /* search w3tc-url-escaping */ ?>"
																	size="70" />
															</td>
															<td>
																<select class="js_file_template js_enabled" <?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
																	<?php foreach ( $templates[ $js_theme ] as $theme_template_key => $theme_template_name ) : ?>
																		<option value="<?php echo esc_attr( $theme_template_key ); ?>"<?php selected( $theme_template_key, $js_template ); ?>>
																			<?php echo esc_attr( $theme_template_name ); ?>
																		</option>
																	<?php endforeach; ?>
																</select>
															</td>
															<td>
																<select class="js_file_location js_enabled" <?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
																	<option value="include" <?php selected( $js_location, 'include' ); ?>><?php esc_html_e( 'Embed in &lt;head&gt;', 'w3-total-cache' ); ?></option>
																	<option value="include-body" <?php selected( $js_location, 'include-body' ); ?>><?php esc_html_e( 'Embed after &lt;body&gt;', 'w3-total-cache' ); ?></option>
																	<option value="include-footer" <?php selected( $js_location, 'include-footer' ); ?>><?php esc_html_e( 'Embed before &lt;/body&gt;', 'w3-total-cache' ); ?></option>
																</select>
															</td>
															<td>
																<input class="js_file_delete js_enabled button" type="button" value="<?php esc_html_e( 'Delete', 'w3-total-cache' ); ?>" />
																<input class="js_file_verify js_enabled button" type="button" value="<?php esc_html_e( 'Verify URI', 'w3-total-cache' ); ?>" />
															</td>
														</tr>
													</table>
												</li>
												<?php
											endforeach;
										endif;
									endforeach;
								endforeach;
							endif;
						endforeach;
						?>
						</ul>
						<div id="js_files_empty" class="w3tc-empty" style="display: none;">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'No %1$sJS%2$s files added',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
									'</acronym>'
								),
								array(
									'acronym' => array(
										'title' => array(),
									),
								)
							);
							?>
						</div>
						<input id="js_file_add" class="js_enabled button" type="button" value="<?php esc_html_e( 'Add a script', 'w3-total-cache' ); ?>" />
					</td>
				</tr>
			<?php endif; ?>
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'minify.js.http2push',
					'label'          => '<acronym title="Hypertext Markup Language">HTTP</acronym>/2 push',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag for HTTP (Hypertext Transfer Protocol), 2 closing HTML acronym tag.
							__(
								'For better performance, send files to browser before they are requested when using the %1$sHTTP%2$s/2 protocol.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					) . (
						'file_generic' !== $this->_config->get_string( 'pgcache.engine' ) ?
						'' :
						wp_kses(
							sprintf(
								// translators: 1 HTML line break tag followed by opening HTML b tag, 2 closing HTML b tag.
								__(
									' %1$sNot supported by "Disk: Enhanced" page cache method for Nginx%2$s',
									'w3-total-cache'
								),
								'<br /><b>',
								'</b>'
							),
							array(
								'br' => array(),
								'b'  => array(),
							)
						)
					),
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'minify_js' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'%1$sCSS%2$s',
					'w3-total-cache'
				),
				'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			'',
			'css'
		);
		?>
		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'minify.css.enable',
					'label'          => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sCSS%2$s minify settings:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				)
			);
			?>
			<?php
			Util_Ui::config_item(
				array(
					'key'              => 'minify.css.method',
					'label'            => __( 'Minify method:', 'w3-total-cache' ),
					'control'          => 'selectbox',
					'selectbox_values' => array(
						'both'    => array(
							'label' => esc_html__( 'Combine & Minify', 'w3-total-cache' ),
						),
						'minify'  => array(
							'label' => esc_html__( 'Minify only', 'w3-total-cache' ),
						),
						'combine' => array(
							'label' => esc_html__( 'Combine only', 'w3-total-cache' ),
						),
					),
				)
			);
			?>
			<tr>
				<th><?php esc_html_e( 'Minify engine settings:', 'w3-total-cache' ); ?></th>
				<td>
					<?php
					$css_engine_file = '';

					switch ( $css_engine ) {
						case 'css':
						case 'yuicss':
						case 'csstidy':
							$css_engine_file = W3TC_INC_DIR . '/options/minify/' . $css_engine . '.php';
							break;
					}

					if ( file_exists( $css_engine_file ) ) {
						include $css_engine_file;
					}
					?>
				</td>
			</tr>
			<tr>
				<th><label for="minify_css_import"><?php Util_Ui::e_config_label( 'minify.css.imports' ); ?></label></th>
				<td>
					<select id="minify_css_import" class="css_enabled" name="minify__css__imports"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
						<?php foreach ( $css_imports_values as $css_imports_key => $css_imports_value ) : ?>
							<option value="<?php echo esc_attr( $css_imports_key ); ?>"<?php selected( $css_imports, $css_imports_key ); ?>>
								<?php echo esc_html( $css_imports_value ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</td>
			</tr>
			<?php
			$css_engine_file2 = '';

			switch ( $css_engine ) {
				case 'css':
				case 'yuicss':
				case 'csstidy':
					$css_engine_file2 = W3TC_INC_DIR . '/options/minify/' . $css_engine . '2.php';
					break;
			}

			if ( file_exists( $css_engine_file2 ) ) {
				include $css_engine_file2;
			}
			?>
			<?php if ( ! $auto ) : ?>
				<tr>
					<th>
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'%1$sCSS%2$s file management:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</th>
					<td>
						<p>
							<label>
								<?php esc_html_e( 'Theme:', 'w3-total-cache' ); ?>
								<select id="css_themes" class="css_enabled" name="css_theme"
									<?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
									<?php foreach ( $themes as $theme_key => $theme_name ) : ?>
										<option value="<?php echo esc_attr( $theme_key ); ?>"<?php selected( $theme_key, $css_theme ); ?>>
											<?php
											echo esc_html( $theme_name );
											if ( $theme_key === $css_theme ) {
												echo ' (active)';
											}
											?>
										</option>
									<?php endforeach; ?>
								</select>
							</label>
							<p class="description"><?php esc_html_e( 'Files are minified by template. First select the theme to manage, then add style sheets used in all templates to the "All Templates" group. Use the menu above to manage style sheets unique to a specific template. If necessary drag &amp; drop to resolve dependency issues (due to incorrect order).', 'w3-total-cache' ); ?></p>
						</p>
						<ul id="css_files" class="minify-files">
							<?php
							foreach ( $css_groups as $css_theme => $css_templates ) :
								if ( isset( $templates[ $css_theme ] ) ) :
									$index = 0;
									foreach ( $css_templates as $css_template => $css_locations ) :
										foreach ( (array) $css_locations as $css_location => $css_config ) :
											if ( ! empty( $css_config['files'] ) ) :
												foreach ( (array) $css_config['files'] as $css_file ) :
													$index++;
													?>
													<li>
														<table>
															<tr>
																<th>&nbsp;</th>
																<th><?php esc_html_e( 'File URI:', 'w3-total-cache' ); ?></th>
																<th colspan="2"><?php esc_html_e( 'Template:', 'w3-total-cache' ); ?></th>
															</tr>
															<tr>
																<td><?php echo esc_html( $index ); ?>.</td>
																<td>
																	<input class="css_enabled" type="text" <?php Util_Ui::sealing_disabled( 'minify.' ); ?>
																		name="css_files[<?php echo esc_attr( $css_theme ); ?>][<?php echo esc_attr( $css_template ); ?>][<?php echo esc_attr( $css_location ); ?>][]"
																		value="<?php echo esc_html( $css_file );  /* search w3tc-url-escaping */ ?>"
																		size="70" /><br />
																</td>
																<td>
																	<select class="css_file_template css_enabled" <?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
																	<?php foreach ( $templates[ $css_theme ] as $theme_template_key => $theme_template_name ) : ?>
																		<option value="<?php echo esc_attr( $theme_template_key ); ?>"<?php selected( $theme_template_key, $css_template ); ?>>
																			<?php echo esc_attr( $theme_template_name ); ?>
																		</option>
																	<?php endforeach; ?>
																	</select>
																</td>
																<td>
																	<input class="css_file_delete css_enabled button" type="button" value="<?php esc_html_e( 'Delete', 'w3-total-cache' ); ?>" />
																	<input class="css_file_verify css_enabled button" type="button" value="<?php esc_html_e( 'Verify URI', 'w3-total-cache' ); ?>" />
																</td>
															</tr>
														</table>
													</li>
													<?php
												endforeach;
											endif;
										endforeach;
									endforeach;
								endif;
							endforeach;
							?>
						</ul>
						<div id="css_files_empty" class="w3tc-empty" style="display: none;">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'No %1$sCSS%2$s files added',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
									'</acronym>'
								),
								array(
									'acronym' => array(
										'title' => array(),
									),
								)
							);
							?>
						</div>
						<input id="css_file_add" class="css_enabled button" type="button" value="<?php esc_html_e( 'Add a style sheet', 'w3-total-cache' ); ?>" />
					</td>
				</tr>
			<?php endif; ?>
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'minify.css.http2push',
					'label'          => '<acronym title="Hypertext Markup Language">HTTP</acronym>/2 push',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag for HTTP (Hypertext Transfer Protocol), 2 closing HTML acronym tag.
							__(
								'For better performance, send files to browser before they are requested when using the %1$sHTTP%2$s/2 protocol.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					) . (
						'file_generic' !== $this->_config->get_string( 'pgcache.engine' ) ?
						'' :
						wp_kses(
							sprintf(
								// translators: 1 HTML line break tag, 2 opening HTML b tag, 3 closing HTML b tag.
								__(
									' %1$s%2$sNot supported by "Disk: Enhanced" page cache method for Nginx%3$s',
									'w3-total-cache'
								),
								'<br />',
								'<b>',
								'</b>'
							),
							array(
								'br' => array(),
								'b'  => array(),
							)
						)
					),
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'minify_css' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Advanced', 'w3-total-cache' ), '', 'advanced' ); ?>
		<table class="form-table">
			<?php
			if ( 'memcached' === $this->_config->get_string( 'minify.engine' ) ) {
				$module = 'minify';
				include W3TC_INC_DIR . '/options/parts/memcached.php';
			} elseif ( 'redis' === $this->_config->get_string( 'minify.engine' ) ) {
				$module = 'minify';
				include W3TC_INC_DIR . '/options/parts/redis.php';
			}
			?>
			<tr>
				<th><label for="minify_lifetime"><?php Util_Ui::e_config_label( 'minify.lifetime' ); ?></label></th>
				<td>
					<input id="minify_lifetime" type="text" name="minify__lifetime"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'minify.lifetime' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'Specify the interval between download and update of external files in the minify cache. Hint: 6 hours is 21600 seconds. 12 hours is 43200 seconds. 24 hours is 86400 seconds.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="minify_file_gc"><?php Util_Ui::e_config_label( 'minify.file.gc' ); ?></label></th>
				<td>
					<input id="minify_file_gc" type="text" name="minify__file__gc"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'minify.file.gc' ) ); ?>" size="8"
						<?php
						if ( 'file' !== $this->_config->get_string( 'minify.engine' ) ) {
							echo ' disabled="disabled"';
						}
						?>
						/> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'If caching to disk, specify how frequently expired cache data is removed. For busy sites, a lower value is best.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="minify_reject_uri"><?php Util_Ui::e_config_label( 'minify.reject.uri' ); ?></label></th>
				<td>
					<textarea id="minify_reject_uri" name="minify__reject__uri"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'minify.reject.uri' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Always ignore the specified pages / directories. Use relative paths. Omit: protocol, hostname, leading forward slash and query strings.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="minify_reject_files_js"><?php Util_Ui::e_config_label( 'minify.reject.files.js' ); ?></label></th>
				<td>
					<textarea id="minify_reject_files_js" name="minify__reject__files__js"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'minify.reject.files.js' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Always ignore the specified %1$sJS%2$s files. Use relative paths. Omit: protocol, hostname, leading forward slash and query strings.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="minify_reject_files_css"><?php Util_Ui::e_config_label( 'minify.reject.files.css' ); ?></label></th>
				<td>
					<textarea id="minify_reject_files_css" name="minify__reject__files__css"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'minify.reject.files.css' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Always ignore the specified %1$sCSS%2$s files. Use relative paths. Omit: protocol, hostname, leading forward slash and query strings.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="minify_reject_ua"><?php Util_Ui::e_config_label( 'minify.reject.ua' ); ?></label></th>
				<td>
					<textarea id="minify_reject_ua" name="minify__reject__ua"
						<?php Util_Ui::sealing_disabled( 'minify.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'minify.reject.ua' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Specify user agents that will never receive minified content.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<?php if ( $auto ) : ?>
			<tr>
				<th><label for="minify_cache_files"><?php Util_Ui::e_config_label( 'minify.cache.files' ); ?></label></th>
				<td>
					<textarea id="minify_cache_files" name="minify__cache__files"<?php Util_Ui::sealing_disabled( 'minify.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'minify.cache.files' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Specify external files/libraries that should be combined.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'minify.cache.files_regexp', false, '', true, null ); ?>
					<?php esc_html_e( 'Use Regular Expressions for file name matching', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'If external script file names vary, use regular expressions in the "Include external files/libraries" field to simplify matching.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<?php endif; ?>
		</table>

		<?php Util_Ui::button_config_save( 'minify_advanced' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Note(s):', 'w3-total-cache' ), '', 'notes' ); ?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<ul>
						<li>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
									// translators: 3 opening HTML a tag to W3TC Browsercache admin page, 4 closing HTML a tag.
									__(
										'Enable %1$sHTTP%2$s compression in the "Cascading Style Sheets &amp; JavaScript" section on %3$sBrowser Cache%4$s Settings tab.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
									'</a>'
								),
								array(
									'acronym' => array(
										'title' => array(),
									),
									'a'       => array(
										'href' => array(),
									),
								)
							);
							?>
						</li>
						<li>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
									// translators: 3 opening HTML a tag to W3TC Browsercache admin, 4 closing HTML a tag.
									__(
										'The %1$sTTL%2$s of page cache files is set via the "Expires header lifetime" field in the "Cascading Style Sheets &amp; JavaScript" section on %3$sBrowser Cache%4$s Settings tab.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Time to Live', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
									'</a>'
								),
								array(
									'acronym' => array(
										'title' => array(),
									),
									'a'       => array(
										'href' => array(),
									),
								)
							);
							?>
						</li>
					</ul>
				</th>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
