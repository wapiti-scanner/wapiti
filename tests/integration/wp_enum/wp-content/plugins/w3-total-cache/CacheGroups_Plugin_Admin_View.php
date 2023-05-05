<?php
/**
 * File: CacheGroups_Plugin_Admin_View.php
 *
 * @since 2.1.0
 *
 * @package W3TC
 *
 * @uses $useragent_groups
 * @uses $useragent_themes
 * @uses $referrer_groups
 * @uses $referrer_themes
 * @uses $cookie_groups
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>

<form id="cachegroups_form" action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">

<!-- User Agenet Groups -->

	<script type="text/javascript">/*<![CDATA[*/
	var mobile_themes = {};
	<?php foreach ( $useragent_themes as $theme_key => $theme_name ) : ?>
	mobile_themes['<?php echo esc_attr( addslashes( $theme_key ) ); ?>'] = '<?php echo esc_html( addslashes( $theme_name ) ); ?>';
	<?php endforeach; ?>
	/*]]>*/</script>

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Manage User Agent Groups', 'w3-total-cache' ), '', 'manage-uag' ); ?>
		<p>
			<input id="mobile_add" type="button" class="button"
				<?php disabled( $useragent_groups['disabled'] ); ?>
				value="<?php esc_html_e( 'Create a group', 'w3-total-cache' ); ?>" />
			<?php esc_html_e( 'of user agents by specifying names in the user agents field. Assign a set of user agents to use a specific theme, redirect them to another domain or if an existing mobile plugin is active, create user agent groups to ensure that a unique cache is created for each user agent group. Drag and drop groups into order (if needed) to determine their priority (top -&gt; down).', 'w3-total-cache' ); ?>
		</p>

		<ul id="mobile_groups">
			<?php
			$index = 0;

			foreach ( $useragent_groups['value'] as $group => $group_config ) :
				$index++;
				?>
			<li id="mobile_group_<?php echo esc_attr( $group ); ?>">
				<table class="form-table">
					<tr>
						<th>
							<?php esc_html_e( 'Group name:', 'w3-total-cache' ); ?>
						</th>
						<td>
							<span class="mobile_group_number"><?php echo esc_attr( $index ); ?>.</span> <span class="mobile_group"><?php echo esc_html( $group ); // phpcs:ignore ?></span>
							<input type="button" class="button mobile_delete"
								value="<?php esc_html_e( 'Delete group', 'w3-total-cache' ); ?>"
								<?php disabled( $useragent_groups['disabled'] ); ?> />
						</td>
					</tr>
					<tr>
						<th>
							<label for="mobile_groups_<?php echo esc_attr( $group ); ?>_enabled"><?php esc_html_e( 'Enabled:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<input type="hidden" name="mobile_groups[<?php echo esc_attr( $group ); ?>][enabled]" value="0" />
							<input id="mobile_groups_<?php echo esc_attr( $group ); ?>_enabled"
								type="checkbox"
								name="mobile_groups[<?php echo esc_attr( $group ); ?>][enabled]"
								<?php disabled( $useragent_groups['disabled'] ); ?> value="1"
								<?php checked( $group_config['enabled'], true ); ?> />
						</td>
					</tr>
					<tr>
						<th>
							<label for="mobile_groups_<?php echo esc_attr( $group ); ?>_theme"><?php esc_html_e( 'Theme:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<select id="mobile_groups_<?php echo esc_attr( $group ); ?>_theme"
								name="mobile_groups[<?php echo esc_attr( $group ); ?>][theme]"
								<?php disabled( $useragent_groups['disabled'] ); ?> >
								<option value=""><?php esc_html_e( '-- Pass-through --', 'w3-total-cache' ); ?></option>
								<?php foreach ( $useragent_themes as $theme_key => $theme_name ) : ?>
								<option value="<?php echo esc_attr( $theme_key ); ?>"<?php selected( $theme_key, $group_config['theme'] ); ?>><?php echo esc_html( $theme_name ); ?></option>
								<?php endforeach; ?>
							</select>
							<p class="description">
								<?php esc_html_e( 'Assign this group of user agents to a specific theme. Selecting "Pass-through" allows any plugin(s) (e.g. mobile plugins) to properly handle requests for these user agents. If the "redirect users to" field is not empty, this setting is ignored.', 'w3-total-cache' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th>
							<label for="mobile_groups_<?php echo esc_attr( $group ); ?>_redirect"><?php esc_html_e( 'Redirect users to:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<input id="mobile_groups_<?php echo esc_attr( $group ); ?>_redirect"
								type="text" name="mobile_groups[<?php echo esc_attr( $group ); ?>][redirect]"
								value="<?php echo esc_attr( $group_config['redirect'] ); ?>"
								<?php disabled( $useragent_groups['disabled'] ); ?>
								size="60" />
							<p class="description"><?php esc_html_e( 'A 302 redirect is used to send this group of users to another hostname (domain); recommended if a 3rd party service provides a mobile version of your site.', 'w3-total-cache' ); ?></p>
						</td>
					</tr>
					<tr>
						<th>
							<label for="mobile_groups_<?php echo esc_attr( $group ); ?>_agents"><?php esc_html_e( 'User agents:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<textarea id="mobile_groups_<?php echo esc_attr( $group ); ?>_agents"
								name="mobile_groups[<?php echo esc_attr( $group ); ?>][agents]"
								rows="10" cols="50" <?php disabled( $useragent_groups['disabled'] ); ?>><?php echo esc_textarea( implode( "\r\n", (array) $group_config['agents'] ) ); ?></textarea>
							<p class="description">
								<?php esc_html_e( 'Specify the user agents for this group. Remember to escape special characters like spaces, dots or dashes with a backslash. Regular expressions are also supported.', 'w3-total-cache' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</li>
			<?php endforeach; ?>
		</ul>
		<div id="mobile_groups_empty" style="display: none;"><?php esc_html_e( 'No groups added. All user agents recieve the same page and minify cache results.', 'w3-total-cache' ); ?></div>

		<?php
		if ( ! $useragent_groups['disabled'] ) {
			Util_Ui::button_config_save( 'mobile' );
		}

		Util_Ui::postbox_footer();

		Util_Ui::postbox_header(
			__( 'Note(s):', 'w3-total-cache' ),
			'',
			'notes'
		);
		?>

		<table class="form-table">
			<tr>
				<th colspan="2">
					<ul>
						<?php echo $useragent_groups['description']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					</ul>
				</th>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>

<!-- Referrer Groups -->

	<script type="text/javascript">/*<![CDATA[*/
		var referrer_themes = {};
		<?php foreach ( $referrer_themes as $theme_key => $theme_name ) : ?>
		referrer_themes['<?php echo esc_attr( $theme_key ); ?>'] = '<?php echo esc_html( $theme_name ); ?>';
		<?php endforeach; ?>
	/*]]>*/</script>

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Manage Referrer Groups', 'w3-total-cache' ), '', 'manage-rg' ); ?>
		<p>
			<input id="referrer_add" type="button" class="button" value="<?php esc_html_e( 'Create a group', 'w3-total-cache' ); ?>" /> <?php esc_html_e( 'of referrers by specifying names in the referrers field. Assign a set of referrers to use a specific theme, redirect them to another domain, create referrer groups to ensure that a unique cache is created for each referrer group. Drag and drop groups into order (if needed) to determine their priority (top -&gt; down).', 'w3-total-cache' ); ?>
		</p>

		<ul id="referrer_groups">
			<?php
			$index = 0;

			foreach ( $referrer_groups as $group => $group_config ) :
				$index++;
				?>
			<li id="referrer_group_<?php echo esc_attr( $group ); ?>">
				<table class="form-table">
					<tr>
						<th>
							<?php esc_html_e( 'Group name:', 'w3-total-cache' ); ?>
						</th>
						<td>
							<span class="referrer_group_number"><?php echo esc_attr( $index ); ?>.</span> <span class="referrer_group"><?php echo esc_html( $group ); ?></span> <input type="button" class="button referrer_delete" value="<?php esc_html_e( 'Delete group', 'w3-total-cache' ); ?>" />
						</td>
					</tr>
					<tr>
						<th>
							<label for="referrer_groups_<?php echo esc_attr( $group ); ?>_enabled"><?php esc_html_e( 'Enabled:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<input type="hidden" name="referrer_groups[<?php echo esc_attr( $group ); ?>][enabled]" value="0" />
							<input id="referrer_groups_<?php echo esc_attr( $group ); ?>_enabled" type="checkbox" name="referrer_groups[<?php echo esc_attr( $group ); ?>][enabled]" value="1"<?php checked( $group_config['enabled'], true ); ?> />
						</td>
					</tr>
					<tr>
						<th>
							<label for="referrer_groups_<?php echo esc_attr( $group ); ?>_theme"><?php esc_html_e( 'Theme:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<select id="referrer_groups_<?php echo esc_attr( $group ); ?>_theme" name="referrer_groups[<?php echo esc_attr( $group ); ?>][theme]">
								<option value=""><?php esc_html_e( '-- Pass-through --', 'w3-total-cache' ); ?></option>
								<?php foreach ( $referrer_themes as $theme_key => $theme_name ) : ?>
								<option value="<?php echo esc_attr( $theme_key ); ?>"<?php selected( $theme_key, $group_config['theme'] ); ?>><?php echo esc_html( $theme_name ); ?></option>
								<?php endforeach; ?>
							</select>
							<p class="description"><?php esc_html_e( 'Assign this group of referrers to a specific theme. Selecting "Pass-through" allows any plugin(s) (e.g. referrer plugins) to properly handle requests for these referrers. If the "redirect users to" field is not empty, this setting is ignored.', 'w3-total-cache' ); ?></p>
						</td>
					</tr>
					<tr>
						<th>
							<label for="referrer_groups_<?php echo esc_attr( $group ); ?>_redirect"><?php esc_html_e( 'Redirect users to:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<input id="referrer_groups_<?php echo esc_attr( $group ); ?>_redirect" type="text" name="referrer_groups[<?php echo esc_attr( $group ); ?>][redirect]" value="<?php echo esc_attr( $group_config['redirect'] ); ?>" size="60" />
							<p class="description"><?php esc_html_e( 'A 302 redirect is used to send this group of referrers to another hostname (domain).', 'w3-total-cache' ); ?></p>
						</td>
					</tr>
					<tr>
						<th>
							<label for="referrer_groups_<?php echo esc_attr( $group ); ?>_referrers"><?php esc_html_e( 'Referrers:', 'w3-total-cache' ); ?></label>
						</th>
						<td>
							<textarea id="referrer_groups_<?php echo esc_attr( $group ); ?>_referrers" name="referrer_groups[<?php echo esc_attr( $group ); ?>][referrers]" rows="10" cols="50"><?php echo esc_textarea( implode( "\r\n", (array) $group_config['referrers'] ) ); ?></textarea>
							<p class="description"><?php esc_html_e( 'Specify the referrers for this group. Remember to escape special characters like spaces, dots or dashes with a backslash. Regular expressions are also supported.', 'w3-total-cache' ); ?></p>
						</td>
					</tr>
				</table>
			</li>
			<?php endforeach; ?>
		</ul>
		<div id="referrer_groups_empty" style="display: none;"><?php esc_html_e( 'No groups added. All referrers recieve the same page and minify cache results.', 'w3-total-cache' ); ?></div>

		<?php Util_Ui::button_config_save( 'referrers' ); ?>
		<?php Util_Ui::postbox_footer(); ?>
	</div>

<!-- Cookie Groups -->

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Manage Cookie Groups', 'w3-total-cache' ), '', 'manage-cg' ); ?>
		<p>
			<input id="w3tc_cookiegroup_add" type="button" class="button"
				<?php disabled( $cookie_groups['disabled'] ); ?>
				value="<?php esc_html_e( 'Create a group', 'w3-total-cache' ); ?>" />
			<?php esc_html_e( 'of Cookies by specifying names in the Cookies field. Assign a set of Cookies to ensure that a unique cache is created for each Cookie group. Drag and drop groups into order (if needed) to determine their priority (top -&gt; down).', 'w3-total-cache' ); ?>
		</p>

		<ul id="cookiegroups" class="w3tc_cachegroups">
			<?php
			$index = 0;
			foreach ( $cookie_groups['value'] as $group => $group_config ) :
				$index++;
				?>
			<li id="cookiegroup_<?php echo esc_attr( $group ); ?>">
				<table class="form-table">
					<tr>
						<th>
							<?php esc_html_e( 'Group name:', 'w3-total-cache' ); ?>
						</th>
						<td>
							<span class="cookiegroup_number"><?php echo esc_attr( $index ); ?>.</span>
							<span class="cookiegroup_name"><?php echo htmlspecialchars( $group ); // phpcs:ignore ?></span>
							<input type="button" class="button w3tc_cookiegroup_delete"
								value="<?php esc_html_e( 'Delete group', 'w3-total-cache' ); ?>"
								<?php disabled( $cookie_groups['disabled'] ); ?> />
						</td>
					</tr>
					<tr>
						<th>
							<label for="cookiegroup_<?php echo esc_attr( $group ); ?>_enabled">
								<?php esc_html_e( 'Enabled:', 'w3-total-cache' ); ?>
							</label>
						</th>
						<td>
							<input id="cookiegroup_<?php echo esc_attr( $group ); ?>_enabled"
								type="checkbox"
								name="cookiegroups[<?php echo esc_attr( $group ); ?>][enabled]"
								<?php disabled( $cookie_groups['disabled'] ); ?> value="1"
								<?php checked( $group_config['enabled'], true ); ?> />
						</td>
					</tr>
					<tr>
						<th>
							<label for="cookiegroup_<?php echo esc_attr( $group ); ?>_cache">
								<?php esc_html_e( 'Cache:', 'w3-total-cache' ); ?>
							</label>
						</th>
						<td>
							<input id="cookiegroup_<?php echo esc_attr( $group ); ?>_cache"
								type="checkbox"
								name="cookiegroups[<?php echo esc_attr( $group ); ?>][cache]"
								<?php disabled( $cookie_groups['disabled'] ); ?> value="1"
								<?php checked( $group_config['cache'], true ); ?> />
						</td>
					</tr>
					<tr>
						<th>
							<label for="cookiegroup_<?php echo esc_attr( $group ); ?>_cookies">
								<?php esc_html_e( 'Cookies:', 'w3-total-cache' ); ?>
							</label>
						</th>
						<td>
							<textarea id="cookiegroup_<?php echo esc_attr( $group ); ?>_cookies"
								name="cookiegroups[<?php echo esc_attr( $group ); ?>][cookies]"
								rows="10" cols="50" <?php disabled( $cookie_groups['disabled'] ); ?>><?php echo esc_textarea( implode( "\r\n", (array) $group_config['cookies'] ) ); ?></textarea>
							<p class="description">
								<?php esc_html_e( 'Specify the cookies for this group. Values like \'cookie\', \'cookie=value\', and cookie[a-z]+=value[a-z]+ are supported. Remember to escape special characters like spaces, dots or dashes with a backslash. Regular expressions are also supported.', 'w3-total-cache' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</li>
			<?php endforeach; ?>
		</ul>
		<div id="cookiegroups_empty" style="display: none;"><?php esc_html_e( 'No groups added. All Cookies recieve the same page and minify cache results.', 'w3-total-cache' ); ?></div>

		<?php
		if ( ! $cookie_groups['disabled'] ) {
			Util_Ui::button_config_save( 'pgcache_cookiegroups' );
		}

		Util_Ui::postbox_footer();

		Util_Ui::postbox_header(
			__( 'Note(s):', 'w3-total-cache' ),
			'',
			'notes'
		);
		?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<ul>
						<li>
							<?php esc_html_e( 'Content is cached for each group separately.', 'w3-total-cache' ); ?>
						</li>
						<li>
							<?php esc_html_e( 'Per the above, make sure that visitors are notified about the cookie as per any regulations in your market.', 'w3-total-cache' ); ?>
						</li>
					</ul>
				</th>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>

</form>
