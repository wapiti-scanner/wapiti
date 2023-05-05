<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<div id="install">
	<h3 id="initial"><?php esc_html_e( 'Initial Installation', 'w3-total-cache' ); ?></h3>
	<ol>
		<li>
			<?php esc_html_e( 'Set the permissions of wp-content/ back to 755, e.g.:', 'w3-total-cache' ); ?>
			<pre class="console"># chmod 755 /var/www/vhosts/domain.com/httpdocs/wp-content/</pre>
		</li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to W3TC General admin page, 2 closing HTML a tag.
					__(
						'On the "%1$sGeneral%2$s" tab and select your caching methods for page, database and minify. In most cases, "disk enhanced" mode for page cache, "disk" mode for minify and "disk" mode for database caching are "good" settings.',
						'w3-total-cache'
					),
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_general' ) ) . '">',
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
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to W3TC PageCache admin page, 2 closing HTML a tag.
					__(
						'1. The "Compatibility Mode" option found in the advanced section of the %1$s"Page Cache Settings"%2$s tab will enable functionality that optimizes the interoperablity of caching with WordPress, is disabled by default, but highly recommended. Years of testing in hundreds of thousands of installations have helped us learn how to make caching behave well with WordPress. The tradeoff is that disk enhanced page cache performance under load tests will be decreased by ~20%% at scale.',
						'w3-total-cache'
					),
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_pgcache' ) ) . '">',
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
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML em tag, 2 closing HTML em tag,
					// translators: 3 opening HTML a tag to W3TC Minify admin page, 4 closing HTML a tag,
					// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag,
					// translators: 7 opening HTML acronym tag, 8 closing HTML acronym tag,
					// translators: 9 opening HTML acronym tag, 10 closing HTML acronym tag,
					// translators: 11 opening HTML a tag to W3TC Redirects FAQ page, 12 opening HTML acronym tag,
					// translators: 13 closing HTML acronym tag, 14 closing HTML a tag.
					__(
						'%1$sRecommended:%2$s On the "%3$sMinify%4$s" tab all of the recommended settings are preset. Use the help button to simplify discovery of your %5$sCSS%6$s and %7$sJS%8$s files and groups. Pay close attention to the method and location of your %9$sJS%10$s group embeddings. See the plugin\'s %11$s%12$sFAQ%13$s%14$s for more information on usage.',
						'w3-total-cache'
					),
					'<em>',
					'</em>',
					'<a href="admin.php?page=w3tc_minify">',
					'</a>',
					'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<a href="' . esc_url( 'https://api.w3-edge.com/v1/redirects/faq/usage' ) . '">',
					'<acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">',
					'</acronym>',
					'</a>'
				),
				array(
					'em'      => array(),
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
					// translators: 1 opening HTML em tag, 2 closing HTML em tag,
					// translators: 3 opening HTML a tag to W3TC BrowserCache admin page, 4 closing HTML a tag,
					// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
					__(
						'%1$sRecommended:%2$s On the "%3$sBrowser Cache%4$s" tab, %5$sHTTP%6$s compression is enabled by default. Make sure to enable other options to suit your goals.',
						'w3-total-cache'
					),
					'<em>',
					'</em>',
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
					'</a>',
					'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'em'      => array(),
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
					// translators: 1 opening HTML em tag, 2 closing HTML em tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag
					// translators: 5 opening HTML a tag to W3TC CDN admin page, 6 closing HTML a tag,
					// translators: 7 opening HTML acronym tag, 8 closing HTML acronym tag,
					// translators: 9 opening HTML acronym tag, 10 closing HTML acronym tag,
					// translators: 11 opening HTML acronym tag, 12 closing HTML acronym tag,
					// translators: 13 opening HTML acronym tag, 14 closing HTML acronym tag.
					__(
						'%1$sRecommended:%2$s If you already have a content delivery network (%3$sCDN%4$s) provider, proceed to the "%5$sContent Delivery Network%6$s" tab and populate the fields and set your preferences. If you do not use the Media Library, you will need to import your images etc into the default locations. Use the Media Library Import Tool on the "Content Delivery Network" tab to perform this task. If you do not have a %7$sCDN%8$s provider, you can still improve your site\'s performance using the "Self-hosted" method. On your own server, create a subdomain and matching %9$sDNS%10$s Zone record; e.g. static.domain.com and configure %11$sFTP%12$s options on the "Content Delivery Network" tab accordingly. Be sure to %13$sFTP%14$s upload the appropriate files, using the available upload buttons.',
						'w3-total-cache'
					),
					'<em>',
					'</em>',
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_cdn' ) ) . '">',
					'</a>',
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Domain Name System', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'a'       => array(
						'herf' => array(),
					),
					'em'      => array(),
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
					// translators: 1 opening HTML em tag, 2 closing HTML em tag,
					// translators: 3 opening HTML a tag to W3TC DatabaseCache admin page, 4 closing HTML a tag.
					__(
						'%1$sOptional:%2$s On the "%3$sDatabase Cache%4$s" tab the recommended settings are preset. If using a shared hosting account use the "disk" method with caution; in either of these cases the response time of the disk may not be fast enough, so this option is disabled by default.',
						'w3-total-cache'
					),
					'<em>',
					'</em>',
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_dbcache' ) ) . '">',
					'</a>'
				),
				array(
					'em' => array(),
					'a'  => array(
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
					// translators: 1 opening HTML em tag, 2 closing HTML em tag,
					// translators: 3 opening HTML a tag to W3TC ObjectCache admin page, 4 closing HTML a tag.
					__(
						'%1$sOptional:%2$s On the "%3$sObject Cache%4$s" tab the recommended settings are preset. If using a shared hosting account use the "disk" method with caution, the response time of the disk may not be fast enough, so this option is disabled by default. Test this option with and without database cache to ensure that it provides a performance increase.',
						'w3-total-cache'
					),
					'<em>',
					'</em>',
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_objectcache' ) ) . '">',
					'</a>'
				),
				array(
					'em' => array(),
					'a'  => array(
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
					// translators: 1 opening HTML em tag, 2 closing HTML em tag,
					// translators: 3 opening HTML a tag to W3TC Cache Groups admin page, 4 closing HTML a tag.
					__(
						'%1$sOptional:%2$s On the "%3$sUser Agent Groups%4$s" tab, specify any user agents, like mobile phones if a mobile theme is used.',
						'w3-total-cache'
					),
					'<em>',
					'</em>',
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_cachegroups' ) ) . '">',
					'</a>'
				),
				array(
					'em' => array(),
					'a'  => array(
						'href' => array(),
					),
				)
			);
			?>
		</li>
	</ol>

	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
				// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
				__(
					'Check out the %1$sFAQ%2$s for more details on %3$susage</a>.',
					'w3-total-cache'
				),
				'<acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">',
				'</acronym>',
				'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_faq' ) ) . '">',
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

	<hr />
	<?php if ( count( $rewrite_rules_descriptors ) ) : ?>
		<h3 id="rules"><?php esc_html_e( 'Rewrite Rules (based on active settings)', 'w3-total-cache' ); ?></h3>
		<?php foreach ( $rewrite_rules_descriptors as $descriptor ) : ?>
			<p><strong><?php echo esc_html( $descriptor['filename'] ); ?>:</strong></p>
			<pre class="code"><?php echo esc_html( $descriptor['content'] ); ?></pre>
		<?php endforeach; ?>
		<hr />
	<?php endif; ?>
	<?php if ( count( $other_areas ) ) : ?>
		<h3 id="other"><?php esc_html_e( 'Other', 'w3-total-cache' ); ?></h3>
		<?php foreach ( $other_areas as $area => $descriptors ) : ?>
			<?php foreach ( $descriptors as $descriptor ) : ?>
				<p><strong><?php echo esc_html( $descriptor['title'] ); ?>:</strong></p>
				<pre class="code"><?php echo esc_html( $descriptor['content'] ); ?></pre>
			<?php endforeach; ?>
		<?php endforeach; ?>
		<hr />
	<?php endif; ?>
	<h3 id="additional"><?php esc_html_e( 'Services', 'w3-total-cache' ); ?></h3>
	<ul>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation"><?php esc_html_e( 'Server Preparation', 'w3-total-cache' ); ?></a>
		</li>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation/memcached"><?php esc_html_e( 'Install Memcached Deamon', 'w3-total-cache' ); ?></a>
		</li>
	</ul>
	<hr />
	<h3 id="modules">
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'%1$sPHP%2$s Modules',
					'w3-total-cache'
				),
				'<acronym title="' . esc_attr__( 'Hypertext Preprocessor', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			array(
				'acronym' => array(
					'title' => array(),
				),
			)
		);
		?>
	</h3>
	<ul>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation/php/memcached"><?php esc_html_e( 'Install Memcached Module', 'w3-total-cache' ); ?></a>
		</li>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation/php/apc">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'Install %1$sAPC%2$s module',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Alternative PHP Cache', 'w3-total-cache' ) . '">',
						'</acronym>'
					),
					array(
						'acronym' => array(
							'title' => array(),
						),
					)
				);
				?>
			</a>
		</li>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation/php/xcache"><?php esc_html_e( 'Install XCache Module', 'w3-total-cache' ); ?></a>
		</li>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation/php/eaccelerator"><?php esc_html_e( 'Install eAccelerator Module', 'w3-total-cache' ); ?></a>
		</li>
		<li>
			<a href="https://api.w3-edge.com/v1/redirects/faq/installation/newrelic"><?php esc_html_e( 'New Relic Module', 'w3-total-cache' ); ?></a>
		</li>
	</ul>

	<hr />

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Note(s):', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<ul>
						<li>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML a tag to W3TC plugin installation FAQs, 2 closing HTML a tag.
									__(
										'Additional installation guides can be found in the %1$swiki%2$s.',
										'w3-total-cache'
									),
									'<a href="' . esc_url( 'https://api.w3-edge.com/v1/redirects/faq/installation' ) . '" target="_blank">',
									'</a>'
								),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
								)
							);
							?>
						</li>
						<li>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML a tag to iss.net, 2 closing HTML a tag,
									// translators: 3 opening HTML a tag to iis.net WinCache for PHP download page, 4 closing HTML a tag.
									__(
										'Best compatibility with %1$sIIS%2$s is realized via %3$sWinCache%4$s opcode cache.',
										'w3-total-cache'
									),
									'<a href="' . esc_url( 'http://www.iis.net/' ) . '" target="_blank">',
									'</a>',
									'<a href="' . esc_url( 'http://www.iis.net/download/wincacheforphp' ) . '" target="_blank">',
									'</a>'
								),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
								)
							);
							?>
						</li>
						<li><?php esc_html_e( 'In the case where Apache is not used, the .htaccess file located in the root directory of the WordPress installation, wp-content/w3tc/pgcache/.htaccess and wp-content/w3tc/min/.htaccess contain directives that must be manually created for your web server software.', 'w3-total-cache' ); ?></li>
						<li><?php esc_html_e( 'Restarting the web server will empty the opcode cache, which means it will have to be rebuilt over time and your site\'s performance will suffer during this period. Still, an opcode cache should be installed in any case to maximize WordPress performance.', 'w3-total-cache' ); ?></li>
						<li><?php esc_html_e( 'Consider using memcached for objects that must persist across web server restarts or that you wish to share amongst your server pool, e.g.: database objects or page cache.', 'w3-total-cache' ); ?></li>
					</ul>
				</th>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</div>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
