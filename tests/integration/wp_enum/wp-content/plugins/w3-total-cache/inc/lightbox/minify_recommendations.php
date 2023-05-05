<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<h3>Minify: Help Wizard</h3>

<p>
	<?php esc_html_e( 'To get started with minify, we\'ve identified the following external CSS and JS objects in the', 'w3-total-cache' ); ?>
	<select id="recom_theme">
		<?php foreach ( $themes as $_theme_key => $_theme_name ) : ?>
			<option value="<?php echo esc_attr( $_theme_key ); ?>"<?php selected( $_theme_key, $theme_key ); ?>><?php echo esc_html( $_theme_name ); ?><?php echo $_theme_key === $theme_key ? '(active)' : ''; ?></option>
		<?php endforeach; ?>
	</select>
	<?php esc_html_e( 'theme. Select "add" the files you wish to minify, then click "apply &amp; close" to save the settings.', 'w3-total-cache' ); ?>
</p>

<div id="recom_container">
	<h4 style="margin-top: 0;">JavaScript:</h4>
	<?php if ( count( $js_groups ) ) : ?>
		<ul id="recom_js_files" class="minify-files">
			<?php
			$index = 0;
			foreach ( $js_groups as $js_group => $js_files ) :
				foreach ( $js_files as $js_file ) :
					$index++;
					?>
					<li>
						<table>
							<tr>
								<th class="minify-files-add"><?php esc_html_e( 'Add:', 'w3-total-cache' ); ?></th>
								<th>&nbsp;</th>
								<th><?php esc_html_e( 'File URI:', 'w3-total-cache' ); ?></th>
								<th><?php esc_html_e( 'Template:', 'w3-total-cache' ); ?></th>
								<th colspan="2"><?php esc_html_e( 'Embed Location:', 'w3-total-cache' ); ?></th>
							</tr>
							<tr>
								<td class="minify-files-add">
									<input type="checkbox" name="recom_js_useit" value="1"<?php checked( isset( $checked_js[ $js_group ][ $js_file ] ), true ); ?> />
								</td>
								<td><?php echo esc_html( $index ); ?>.</td>
								<td>
									<input type="text" name="recom_js_file" value="<?php echo esc_attr( $js_file );  /* search w3tc-url-escaping */ ?>" size="70" />
								</td>
								<td>
									<select name="recom_js_template">
										<?php foreach ( $templates as $template_key => $template_name ) : ?>
											<option value="<?php echo esc_attr( $template_key ); ?>"<?php selected( $template_key, $js_group ); ?>><?php echo esc_html( $template_name ); ?></option>
										<?php endforeach; ?>
									</select>
								</td>
								<td>
									<?php $selected = ( isset( $locations_js[ $js_group ][ $js_file ] ) ? $locations_js[ $js_group ][ $js_file ] : '' ); ?>
									<select name="recom_js_location">
										<option value="include"<?php selected( $selected, 'include' ); ?>><?php esc_html_e( 'Embed in &lt;head&gt;', 'w3-total-cache' ); ?></option>
										<option value="include-body"<?php selected( $selected, 'include-body' ); ?>><?php esc_html_e( 'Embed after &lt;body&gt;', 'w3-total-cache' ); ?></option>
										<option value="include-footer"<?php selected( $selected, 'include-footer' ); ?>><?php esc_html_e( 'Embed before &lt;/body&gt;', 'w3-total-cache' ); ?></option>
									</select>
								</td>
								<td>
									<input class="js_file_verify button" type="button" value="<?php esc_html_e( 'Verify URI', 'w3-total-cache' ); ?>" />
								</td>
							</tr>
						</table>
					</li>
				<?php endforeach; ?>
			<?php endforeach; ?>
		</ul>
		<p>
			<a href="#" id="recom_js_check"><?php esc_html_e( 'Check / Uncheck All', 'w3-total-cache' ); ?></a>
		</p>
	<?php else : ?>
		<p><?php esc_html_e( 'No files found.', 'w3-total-cache' ); ?></p>
	<?php endif; ?>

	<h4><?php esc_html_e( 'Cascading Style Sheets:', 'w3-total-cache' ); ?></h4>

	<?php if ( count( $css_groups ) ) : ?>
		<ul id="recom_css_files" class="minify-files">
			<?php
			$index = 0;
			foreach ( $css_groups as $css_group => $css_files ) :
				foreach ( $css_files as $css_file ) :
					$index++;
					?>
					<li>
						<table>
							<tr>
								<th class="minify-files-add"><?php esc_html_e( 'Add:', 'w3-total-cache' ); ?></th>
								<th>&nbsp;</th>
								<th><?php esc_html_e( 'File URI:', 'w3-total-cache' ); ?></th>
								<th colspan="2"><?php esc_html_e( 'Template:', 'w3-total-cache' ); ?></th>
							</tr>
							<tr>
								<td class="minify-files-add">
									<input type="checkbox" name="recom_css_useit" value="1"<?php checked( isset( $checked_css[ $css_group ][ $css_file ] ), true ); ?> />
								</td>
								<td><?php echo esc_html( $index ); ?>.</td>
								<td>
									<input type="text" name="recom_css_file" value="<?php echo esc_html( $css_file ); /* search w3tc-url-escaping */ ?>" size="70" />
								</td>
								<td>
									<select name="recom_css_template">
										<?php foreach ( $templates as $template_key => $template_name ) : ?>
											<option value="<?php echo esc_attr( $template_key ); ?>"<?php selected( $template_key, $css_group ); ?>><?php echo esc_html( $template_name ); ?></option>
										<?php endforeach; ?>
									</select>
								</td>
								<td>
									<input class="css_file_verify button" type="button" value="<?php esc_html_e( 'Verify URI', 'w3-total-cache' ); ?>" />
								</td>
							</tr>
						</table>
					</li>
				<?php endforeach; ?>
			<?php endforeach; ?>
		</ul>
		<p>
			<a href="#" id="recom_css_check"><?php esc_html_e( 'Check / Uncheck All', 'w3-total-cache' ); ?></a>
		</p>
	<?php else : ?>
		<p>No files found.</p>
	<?php endif; ?>
</div>

<div id="recom_container_bottom">
	<p>
		<input class="recom_apply button-primary" type="button" value="<?php esc_attr_e( 'Apply &amp; close', 'w3-total-cache' ); ?>" />
	</p>

	<fieldset>
		<legend><?php esc_html_e( 'Notes', 'w3-total-cache' ); ?></legend>

		<ul>
			<li><?php esc_html_e( 'Typically minification of advertiser code, analytics/statistics or any other types of tracking code is not recommended.', 'w3-total-cache' ); ?></li>
			<li>
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML a tag to W3TC plugin config support page, 2 closing HTML a tag.
						__(
							'Scripts that were not already detected above may require %1$sprofessional consultation%2$s to implement.',
							'w3-total-cache'
						),
						'<a href="admin.php?page=w3tc_support&amp;request_type=plugin_config">',
						'</a>'
					),
					array(
						'a' => array(
							'href' => array(),
						),
					)
				);
				?>
			</li>
		</ul>
	</fieldset>
</div>
