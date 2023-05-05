<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 HTML strong tag containing PageCache Engine name, 2 HTML span tag containing PageCache Engine enabled/disabled.
				__(
					'Page caching via %1$s is currently %2$s',
					'w3-total-cache'
				),
				'<strong>' . esc_html( Cache::engine_name( $this->_config->get_string( 'pgcache.engine' ) ) ) . '</strong>',
				'<span class="w3tc-' . ( $pgcache_enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>.'
			),
			array(
				'strong' => array(),
				'span'   => array(
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
				// translators: 1 Nonce Field followed by submit HTML input to flush PageCache.
				__(
					'To rebuild the page cache use the %1$s operation',
					'w3-total-cache'
				),
				Util_Ui::nonce_field( 'w3tc' ) . '<input type="submit" name="w3tc_flush_pgcache" value="empty cache"' . disabled( $pgcache_enabled, false, false ) . ' class="button" />'
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

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '', 'general' ); ?>
		<table class="form-table">
			<tr>
				<th>
					<?php $this->checkbox( 'pgcache.cache.home' ); ?> <?php Util_Ui::e_config_label( 'pgcache.cache.home' ); ?></label>
					<p class="description"><?php esc_html_e( 'For many blogs this is your most visited page, it is recommended that you cache it.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<?php if ( 'posts' !== get_option( 'show_on_front' ) ) : ?>
				<tr>
					<th>
						<?php $this->checkbox( 'pgcache.reject.front_page' ); ?> <?php Util_Ui::e_config_label( 'pgcache.reject.front_page' ); ?></label>
						<p class="description"><?php esc_html_e( 'By default the front page is cached when using static front page in reading settings.', 'w3-total-cache' ); ?></p>
					</th>
				</tr>
			<?php endif; ?>
			<tr>
				<th>
					<?php $this->checkbox( 'pgcache.cache.feed' ); ?> <?php Util_Ui::e_config_label( 'pgcache.cache.feed' ); ?></label>
					<p class="description"><?php esc_html_e( 'Even if using a feed proxy service enabling this option is still recommended.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<?php $this->checkbox( 'pgcache.cache.ssl' ); ?> <?php Util_Ui::e_config_label( 'pgcache.cache.ssl' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Cache %1$sSSL%2$s requests (uniquely) for improved performance.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Secure Socket Layer', 'w3-total-cache' ) . '">',
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
				<th>
					<?php
					$this->checkbox(
						'pgcache.cache.query',
						( 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ),
						'',
						true,
						( 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ? 0 : null )
					);
					?>
					<?php Util_Ui::e_config_label( 'pgcache.cache.query', 'settings' ); ?></label>
					<p class="description"><?php esc_html_e( 'Search result (and similar) pages will be cached if enabled.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<?php $this->checkbox( 'pgcache.cache.404' ); ?> <?php Util_Ui::e_config_label( 'pgcache.cache.404' ); ?></label>
					<p class="description"><?php esc_html_e( 'Reduce server load by caching 404 pages. If the disk enhanced method of disk caching is used, 404 pages will be returned with a 200 response code. Use at your own risk.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<?php $this->checkbox( 'pgcache.reject.logged' ); ?> <?php Util_Ui::e_config_label( 'pgcache.reject.logged' ); ?></label>
					<p class="description"><?php esc_html_e( 'Unauthenticated users may view a cached version of the last authenticated user\'s view of a given page. Disabling this option is not recommended.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<?php $this->checkbox( 'pgcache.reject.logged_roles' ); ?> <?php Util_Ui::e_config_label( 'pgcache.reject.logged_roles' ); ?></label>
					<p class="description"><?php esc_html_e( 'Select user roles that should not receive cached pages:', 'w3-total-cache' ); ?></p>

					<div id="pgcache_reject_roles" class="w3tc_reject_roles">
						<?php $saved_roles = $this->_config->get_array( 'pgcache.reject.roles' ); ?>
						<input type="hidden" name="pgcache__reject__roles" value="" /><br />
						<?php foreach ( get_editable_roles() as $role_name => $role_data ) : ?>
							<input type="checkbox" name="pgcache__reject__roles[]" value="<?php echo esc_attr( $role_name ); ?>" <?php checked( in_array( $role_name, $saved_roles, true ) ); ?> id="role_<?php echo esc_attr( $role_name ); ?>" />
							<label for="role_<?php echo esc_attr( $role_name ); ?>"><?php echo esc_html( $role_data['name'] ); ?></label>
						<?php endforeach; ?>
					</div>
				</th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'pagecache_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Aliases', 'w3-total-cache' ), '', 'mirrors' ); ?>
		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'pgcache.mirrors.enabled',
					'control'        => 'checkbox',
					'label'          => esc_html__( 'Cache alias hostnames:', 'w3-total-cache' ),
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'enabled'        => ! Util_Environment::is_wpmu_subdomain(),
					'description'    => esc_html__( 'If the same WordPress content is accessed from different domains', 'w3-total-cache' ),
				)
			);
			Util_Ui::config_item(
				array(
					'key'         => 'pgcache.mirrors.home_urls',
					'control'     => 'textarea',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opneing HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Additional home %1$sURL%2$ss:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'enabled'     => ! Util_Environment::is_wpmu_subdomain(),
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag, 3 HTML line break tag,
							// translators: 4 HTML line break tag, 5 HTML line break tag.
							__(
								'Specify full home %1$sURL%2$ss of your mirrors so that plugin will flush it\'s cache when content is changed. For example:%3$s http://my-site.com%4$shttp://www.my-site.com%5$shttps://my-site.com',
								'w3-total-cache'
							),
							'<acronym title="Uniform Resource Locator">',
							'</acronym>',
							'<br />',
							'<br />',
							'<br />'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
							'br'      => array(),
						)
					),
				)
			);
			?>
		</table>
		<?php Util_Ui::button_config_save( 'pagecache_aliases' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Cache Preload', 'w3-total-cache' ), '', 'cache_preload' ); ?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'pgcache.prime.enabled' ); ?> <?php Util_Ui::e_config_label( 'pgcache.prime.enabled' ); ?></label><br />
				</th>
			</tr>
			<tr>
				<th><label for="pgcache_prime_interval"><?php Util_Ui::e_config_label( 'pgcache.prime.interval' ); ?></label></th>
				<td>
					<input id="pgcache_prime_interval" type="text" name="pgcache__prime__interval"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'pgcache.prime.interval' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'The number of seconds to wait before creating another set of cached pages.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_prime_limit"><?php Util_Ui::e_config_label( 'pgcache.prime.limit' ); ?></label></th>
				<td>
					<input id="pgcache_prime_limit" type="text" name="pgcache__prime__limit"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'pgcache.prime.limit' ) ); ?>" size="8" />
					<p class="description"><?php esc_html_e( 'Limit the number of pages to create per batch. Fewer pages may be better for under-powered servers.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_prime_sitemap"><?php Util_Ui::e_config_label( 'pgcache.prime.sitemap' ); ?></label></th>
				<td>
					<input id="pgcache_prime_sitemap" type="text" name="pgcache__prime__sitemap"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_string( 'pgcache.prime.sitemap' ) ); ?>" size="100" />
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to XML Sitemap Validator tool, 2 closing HTML a tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'A %1$scompliant%2$s sitemap can be used to specify the pages to maintain in the primed cache. Pages will be cached according to the priorities specified in the %3$sXML%4$s file.',
									'w3-total-cache'
								),
								'<a href="' . esc_url( 'http://www.xml-sitemaps.com/validate-xml-sitemap.html' ) . '" target="_blank">',
								'</a>',
								'<acronym title="' . esc_attr__( 'Extensible Markup Language', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'a'       => array(
									'href'   => array(),
									'target' => array(),
								),
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
				<th colspan="2">
					<?php $this->checkbox( 'pgcache.prime.post.enabled' ); ?> <?php Util_Ui::e_config_label( 'pgcache.prime.post.enabled' ); ?></label><br />                </th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'pagecache_cache_preload' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		$modules = array();
		if ( $pgcache_enabled ) {
			$modules[] = 'Page Cache';
		}
		if ( $varnish_enabled ) {
			$modules [] = 'Reverse Proxy';
		}
		if ( $cdnfsd_enabled ) {
			$modules[] = 'CDN';
		}
		Util_Ui::postbox_header( esc_html__( 'Purge Policy: ', 'w3-total-cache' ) . implode( ', ', $modules ), '', 'purge_policy' );
		?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php esc_html_e( 'Specify the pages and feeds to purge when posts are created, edited, or comments posted. The defaults are recommended because additional options may reduce server performance:', 'w3-total-cache' ); ?>

					<table border="0" cellpadding="0" cellspacing="0">
						<tr>
							<th style="padding-left: 0;">
								<?php if ( 'posts' !== get_option( 'show_on_front' ) ) : ?>
									<?php $this->checkbox( 'pgcache.purge.front_page' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.front_page' ); ?></label><br />
								<?php endif; ?>
								<?php $this->checkbox( 'pgcache.purge.home' ); ?>  <?php Util_Ui::e_config_label( 'pgcache.purge.home' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.post' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.post' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.feed.blog' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.feed.blog' ); ?></label><br />

							</th>
							<th>
								<?php $this->checkbox( 'pgcache.purge.comments' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.comments' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.author' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.author' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.terms' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.terms' ); ?></label><br />
							</th>
							<th>
								<?php $this->checkbox( 'pgcache.purge.feed.comments' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.feed.comments' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.feed.author' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.feed.author' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.feed.terms' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.feed.terms' ); ?></label>
							</th>
							<th>
								<?php $this->checkbox( 'pgcache.purge.archive.daily' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.archive.daily' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.archive.monthly' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.archive.monthly' ); ?></label><br />
								<?php $this->checkbox( 'pgcache.purge.archive.yearly' ); ?> <?php Util_Ui::e_config_label( 'pgcache.purge.archive.yearly' ); ?></label><br />
							</th>
						</tr>
					</table>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php Util_Ui::e_config_label( 'pgcache.purge.feed.types' ); ?><br />
					<input type="hidden" name="pgcache__purge__feed__types" value="" />
					<?php foreach ( $feeds as $feed ) : ?>
						<label>
							<input type="checkbox" name="pgcache__purge__feed__types[]"
								value="<?php echo esc_attr( $feed ); ?>"
								<?php checked( in_array( $feed, $this->_config->get_array( 'pgcache.purge.feed.types' ), true ), true ); ?>
								<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
								/>
						<?php echo esc_html( $feed ); ?>
						<?php echo $feed === $default_feed ? '(default)' : ''; ?></label><br />
					<?php endforeach; ?>
				</th>
			</tr>
			<tr>
				<th><label for="pgcache_purge_postpages_limit"><?php Util_Ui::e_config_label( 'pgcache.purge.postpages_limit' ); ?></label></th>
				<td>
					<input id="pgcache_purge_postpages_limit" name="pgcache__purge__postpages_limit" <?php Util_Ui::sealing_disabled( 'pgcache.' ); ?> type="text" value="<?php echo esc_attr( $this->_config->get_integer( 'pgcache.purge.postpages_limit' ) ); ?>" />
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 HTML line break tag.
								__(
									'Specify number of pages that lists posts (archive etc) that should be purged on post updates etc, i.e example.com/ ... example.com/page/5. %1$s0 means all pages that lists posts are purged, i.e example.com/page/2 ... .',
									'w3-total-cache'
								),
								'<br />'
							),
							array(
								'br' => array(),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_purge_pages"><?php Util_Ui::e_config_label( 'pgcache.purge.pages' ); ?></label></th>
				<td>
					<textarea id="pgcache_purge_pages" name="pgcache__purge__pages"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
							cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.purge.pages' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Specify additional pages to purge. Including parent page in path. Ex: parent/posts.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_purge_sitemap_regex"><?php Util_Ui::e_config_label( 'pgcache.purge.sitemap_regex' ); ?></label></th>
				<td>
					<input id="pgcache_purge_sitemap_regex" name="pgcache__purge__sitemap_regex" <?php Util_Ui::sealing_disabled( 'pgcache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'pgcache.purge.sitemap_regex' ) ); ?>" type="text" />
					<p class="description"><?php esc_html_e( 'Specify a regular expression that matches your sitemaps.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'pagecache_purge_policy' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header(
			wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1$sREST%2$s %3$sAPI%4$s',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'REpresentational State Transfer', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'',
			'rest'
		);
		?>
		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'                  => 'pgcache.rest',
					'label'                => '<acronym title="REpresentational State Transfer">REST</acronym> <acronym title="Application Programming Interface">API</acronym>',
					'control'              => 'radiogroup',
					'radiogroup_values'    => array(
						''        => __( 'Don\'t cache', 'w3-total-cache' ),
						'cache'   => array(
							'label'           => __( 'Cache', 'w3-total-cache' ),
							'disabled'        => ! Util_Environment::is_w3tc_pro( $this->_config ),
							'pro_feature'     => true,
							'pro_excerpt'     => esc_html__( 'If you\'re using the WordPress API make sure to use caching to scale performance.', 'w3-total-cache' ),
							'pro_description' => array(
								esc_html__( 'If you use WordPress as a backend for integrations, API caching may be for you. Similar to page caching, repeat requests will benefit by having significantly lower response times and consume fewer resources to deliver. If WordPress is not used as a backend, for additional security, the API can be disabled completely.', 'w3-total-cache' ),
							),
						),
						'disable' => wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'Disable %1$sREST%2$s %3$sAPI%4$s',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'REpresentational State Transfer', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						),
					),
					'radiogroup_separator' => '<br />',
					'description'          => wp_kses(
						sprintf(
							// translators: 1 opneing HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opneing HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'Controls WordPress %1$sREST%2$s %3$sAPI%4$s functionality.',
								'w3-total-cache'
							),
							'<acronym title="REpresentational State Transfer">',
							'</acronym>',
							'<acronym title="Application Programming Interface">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
				)
			);
			?>
		</table>
		<?php Util_Ui::button_config_save( 'rest' ); ?>
		<?php Util_Ui::postbox_footer(); ?>


		<?php Util_Ui::postbox_header( esc_html__( 'Advanced', 'w3-total-cache' ), '', 'advanced' ); ?>
		<table class="form-table">
			<tr>
				<th><label for="pgcache_late_init"><?php esc_html_e( 'Late initialization:', 'w3-total-cache' ); ?></label></th>
				<td>
					<input type="hidden" name="pgcache__late_init" value="0" />
					<label><input id="pgcache_late_init" type="checkbox" name="pgcache__late_init" value="1"<?php checked( 'file_generic' !== $this->_config->get_string( 'pgcache.engine' ) && $this->_config->get_boolean( 'pgcache.late_init' ) ); ?> <?php disabled( $this->_config->get_string( 'pgcache.engine' ), 'file_generic' ); ?> /> <?php esc_html_e( 'Enable', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Enables support for WordPress functionality in fragment caching for the page caching engine. Use of this feature may increase response times.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_late_caching"><?php esc_html_e( 'Late caching:', 'w3-total-cache' ); ?></label></th>
				<td>
					<input type="hidden" name="pgcache__late_caching" value="0" />
					<label><input id="pgcache_late_caching" type="checkbox" name="pgcache__late_caching" value="1"<?php checked( 'file_generic' !== $this->_config->get_string( 'pgcache.engine' ) && $this->_config->get_boolean( 'pgcache.late_caching' ) ); ?> <?php disabled( $this->_config->get_string( 'pgcache.engine' ), 'file_generic' ); ?> /> <?php esc_html_e( 'Enable', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Overwrites key of page caching via custom filters by postponing entry extraction during the init action.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<?php
			if ( 'memcached' === $this->_config->get_string( 'pgcache.engine' ) || 'nginx_memcached' === $this->_config->get_string( 'pgcache.engine' ) ) {
				$module = 'pgcache';
				include W3TC_INC_DIR . '/options/parts/memcached.php';
			} elseif ( 'redis' === $this->_config->get_string( 'pgcache.engine' ) ) {
				$module = 'pgcache';
				include W3TC_INC_DIR . '/options/parts/redis.php';
			}
			?>
			<?php if ( 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ) : ?>
				<tr>
					<th><label><?php esc_html_e( 'Compatibility mode:', 'w3-total-cache' ); ?></label></th>
					<td>
						<?php $this->checkbox( 'pgcache.compatibility' ); ?> <?php Util_Ui::e_config_label( 'pgcache.compatibility' ); ?></label>
						<p class="description"><?php esc_html_e( 'Decreases performance by ~20% at scale in exchange for increasing interoperability with more hosting environments and WordPress idiosyncrasies. Enable this option if you experience issues with the Apache rules.', 'w3-total-cache' ); ?></p>
					</td>
				</tr>
				<?php if ( ! Util_Environment::is_nginx() ) : ?>
					<tr>
						<th><label><?php esc_html_e( 'Charset:', 'w3-total-cache' ); ?></label></th>
						<td>
							<?php $this->checkbox( 'pgcache.remove_charset' ); ?> <?php Util_Ui::e_config_label( 'pgcache.remove_charset' ); ?></label>
							<p class="description"><?php esc_html_e( 'Resolve issues incorrect odd character encoding that may appear in cached pages.', 'w3-total-cache' ); ?></p>
						</td>
					</tr>
				<?php endif; ?>
				<tr>
					<th><label for="pgcache_reject_request_head"><?php esc_html_e( 'Reject HEAD requests:', 'w3-total-cache' ); ?></label></th>
					<td>
						<?php if ( 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ) : ?>
							<input id="pgcache_reject_request_head" type="checkbox" name="pgcache__reject__request_head" value="1" disabled="disabled" /> <?php Util_Ui::e_config_label( 'pgcache.reject.request_head' ); ?>
						<?php else : ?>
							<?php $this->checkbox( 'pgcache.reject.request_head', false, '', false ); ?><?php Util_Ui::e_config_label( 'pgcache.reject.request_head' ); ?>
						<?php endif; ?>
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'If disabled, HEAD requests can often be cached resulting in "empty pages" being returned for subsequent requests for a %1$sURL%2$s.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
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
			<?php endif; ?>
			<?php if ( 'file_generic' !== $this->_config->get_string( 'pgcache.engine' ) ) : ?>
				<tr>
					<th><label for="pgcache_lifetime"><?php Util_Ui::e_config_label( 'pgcache.lifetime' ); ?></label></th>
					<td>
						<input id="pgcache_lifetime" type="text" name="pgcache__lifetime"
							<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
							value="<?php echo esc_attr( $this->_config->get_integer( 'pgcache.lifetime' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
						<p class="description"><?php esc_html_e( 'Determines the natural expiration time of unchanged cache items. The higher the value, the larger the cache.', 'w3-total-cache' ); ?></p>
					</td>
				</tr>
			<?php endif; ?>
			<tr>
				<th><label for="pgcache_file_gc"><?php Util_Ui::e_config_label( 'pgcache.file.gc' ); ?></label></th>
				<td>
					<input id="pgcache_file_gc" type="text" name="pgcache__file__gc"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'pgcache.file.gc' ) ); ?>" size="8"<?php echo ( 'file' !== $this->_config->get_string( 'pgcache.engine' ) && 'file_generic' !== $this->_config->get_string( 'pgcache.engine' ) ) ? ' disabled="disabled"' : ''; ?> /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'If caching to disk, specify how frequently expired cache data is removed. For busy sites, a lower value is best.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_comment_cookie_ttl"><?php Util_Ui::e_config_label( 'pgcache.comment_cookie_ttl' ); ?></label></th>
				<td>
						<input id="pgcache_comment_cookie_ttl" type="text" name="pgcache__comment_cookie_ttl" value="<?php echo esc_attr( $this->_config->get_integer( 'pgcache.comment_cookie_ttl' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
									// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
									__(
										'Significantly reduce the default %1$sTTL%2$s for comment cookies to reduce the number of authenticated user traffic. Enter -1 to revert to default %3$sTTL%4$s.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Time to Live', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<acronym title="' . esc_attr__( 'Time to Live', 'w3-total-cache' ) . '">',
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
				<th><label for="pgcache_accept_qs"><?php Util_Ui::e_config_label( 'pgcache.accept.qs' ); ?></label></th>
				<td>
					<textarea id="pgcache_accept_qs" name="pgcache__accept__qs"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.accept.qs' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Always cache %1$sURL%2$ss that use these query string name-value pairs. The value part is not required. But if used, separate name-value pairs with an equals sign (i.e., name=value). Each pair should be on their own line.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
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
				<th><label for="pgcache_reject_ua"><?php Util_Ui::e_config_label( 'pgcache.reject.ua' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_ua" name="pgcache__reject__ua"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.ua' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Never send cache pages for these user agents.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_reject_cookie"><?php Util_Ui::e_config_label( 'pgcache.reject.cookie' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_cookie" name="pgcache__reject__cookie"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.cookie' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Never cache pages that use the specified cookies.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_reject_uri"><?php Util_Ui::e_config_label( 'pgcache.reject.uri' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_uri" name="pgcache__reject__uri"
						w3tc-data-validator="regexps"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.uri' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to W3TC Github FAQ page for which textareas for file entries support regular expressions,
								// translators: 2 opening HTML acronym tag, 3 closing HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'Always ignore the specified pages / directories. Supports regular expressions (See %1$s%2$sFAQ%3$s%4$s)',
									'w3-total-cache'
								),
								'<a href="' . esc_url( 'https://github.com/BoldGrid/w3-total-cache/wiki/FAQ:-Usage#which-textareas-for-file-entries-support-regular-expressions' ) . '">',
								'<acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">',
								'</acronym>',
								'</a>'
							),
							array(
								'a'       => array(
									'href' => array(),
								),
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
				<th><label for="pgcache_reject_categories"><?php Util_Ui::e_config_label( 'pgcache.reject.categories' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_categories" name="pgcache__reject__categories"
						<?php Util_Ui::sealing_disabled( 'pgcache' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.categories' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Always ignore all pages filed under the specified category slugs.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_reject_tags"><?php Util_Ui::e_config_label( 'pgcache.reject.tags' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_tags" name="pgcache__reject__tags"
						<?php Util_Ui::sealing_disabled( 'pgcache' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.tags' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Always ignore all pages filed under the specified tag slugs.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_reject_authors"><?php Util_Ui::e_config_label( 'pgcache.reject.authors' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_authors" name="pgcache__reject__authors"
						<?php Util_Ui::sealing_disabled( 'pgcache' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.authors' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Always ignore all pages filed under the specified author usernames.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_reject_custom"><?php Util_Ui::e_config_label( 'pgcache.reject.custom' ); ?></label></th>
				<td>
					<textarea id="pgcache_reject_custom" name="pgcache__reject__custom"
						<?php Util_Ui::sealing_disabled( 'pgcache' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.reject.custom' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Always ignore all pages filed under the specified custom fields. Separate name-value pairs with an equals sign (i.e., name=value).', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="pgcache_accept_files"><?php Util_Ui::e_config_label( 'pgcache.accept.files' ); ?></label></th>
				<td>
					<textarea id="pgcache_accept_files" name="pgcache__accept__files"
						w3tc-data-validator="regexps"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.accept.files' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to W3TC FAQ admin page, 2 opening HTML acronym tag,
								// translators: 3 closing HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'Cache the specified pages / directories even if listed in the "never cache the following pages" field. Supports regular expression (See %1$s%2$sFAQ%3$s%4$s)',
									'w3-total-cache'
								),
								'<a href="' . esc_url( network_admin_url( 'admin.php?page=w3tc_faq' ) ) . '">',
								'<acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">',
								'</acronym>',
								'</a>'
							),
							array(
								'a'       => array(
									'href' => array(),
								),
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<?php if ( substr( $permalink_structure, -1 ) === '/' ) : ?>
				<tr>
					<th><label for="pgcache_accept_uri"><?php Util_Ui::e_config_label( 'pgcache.accept.uri' ); ?></label></th>
					<td>
						<textarea id="pgcache_accept_uri" name="pgcache__accept__uri"
							w3tc-data-validator="regexps"
							<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
							cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.accept.uri' ) ) ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Cache the specified pages even if they don\'t have trailing slash.', 'w3-total-cache' ); ?></p>
					</td>
				</tr>
			<?php endif; ?>
			<tr>
				<th><label for="pgcache_cache_headers"><?php Util_Ui::e_config_label( 'pgcache.cache.headers' ); ?></label></th>
				<td>
					<textarea id="pgcache_cache_headers" name="pgcache__cache__headers"
						<?php Util_Ui::sealing_disabled( 'pgcache.' ); ?>
						cols="40" rows="5"<?php echo 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ? ' disabled="disabled"' : ''; ?>><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'pgcache.cache.headers' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Specify additional page headers to cache.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<?php if ( 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ) : ?>
				<tr>
					<th><label><?php Util_Ui::e_config_label( 'pgcache.cache.nginx_handle_xml' ); ?></label></th>
					<td>
						<?php $this->checkbox( 'pgcache.cache.nginx_handle_xml' ); ?> <?php Util_Ui::e_config_label( 'pgcache.cache.nginx_handle_xml' ); ?></label>
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Return correct Content-Type header for %1$sXML%2$s files (e.g., feeds and sitemaps). Slows down cache engine.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Extensible Markup Language', 'w3-total-cache' ) . '">',
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
			<?php endif; ?>
		</table>

		<?php Util_Ui::button_config_save( 'pagecache_advanced' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Note(s)', 'w3-total-cache' ), '', 'notes' ); ?>
		<table class="form-table">
			<tr>
				<th>
					<ul>
						<li>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
									// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
									// translators: 5 opening HTML a tag to W3TC BrowserCache admin page, 6 closing HTML a tag.
									__(
										'Enable %1$sHTTP%2$s compression in the "%3$sHTML%4$s" section on %5$sBrowser Cache</a> Settings tab.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
									'</a>'
								),
								array(
									'a'       => array(
										'href' => array(),
									),
									'acronym' => array(
										'title' => array(),
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
									// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
									// translators: 5 opening HTML a tag to W3TC BrowserCache admin page, 6 closing HTML a tag.
									__(
										'The %1$sTTL%2$s of page cache files is set via the "Expires header lifetime" field in the "%3$sHTML%4$s" section on %5$sBrowser Cache%6$s Settings tab.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Time to Live', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
									'</a>'
								),
								array(
									'a'       => array(
										'href' => array(),
									),
									'acronym' => array(
										'title' => array(),
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
