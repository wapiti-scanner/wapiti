<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<div id="about">
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 HTML a tag to memcached.org, 2 HTML acronym open tag, 3 HTML acronym and close tag.
				__(
					'User experience is an important aspect of every web site and all web sites can benefit from effective caching and file size reduction. We have applied web site optimization methods typically used with high traffic sites and simplified their implementation. Coupling these methods either %1$s and/or opcode caching and the %2$sCDN%3$s of your choosing to provide the following features and benefits:',
					'w3-total-cache'
				),
				'<a href="http://memcached.org/" target="_blank">memcached</a>',
				'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
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
	<ul>
		<li><?php esc_html_e( 'Improved Google search engine ranking', 'w3-total-cache' ); ?></li>
		<li><?php esc_html_e( 'Increased visitor time on site', 'w3-total-cache' ); ?></li>
		<li><?php esc_html_e( 'Optimized progressive render (pages start rendering immediately)', 'w3-total-cache' ); ?></li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'Reduced %1$sHTTP%2$s Transactions, %3$sDNS%4$s lookups and reduced document load time',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Domain Name System', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
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
					// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
					__(
						'Bandwidth savings via Minify and %1$sHTTP%2$s compression of %3$sHTML%4$s, %5$sCSS%6$s, JavaScript and feeds',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
					'</acronym>',
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
		</li>
		<li><?php esc_html_e( 'Increased web server concurrency and increased scale (easily sustain high traffic spikes)', 'w3-total-cache' ); ?></li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Transparent content delivery network (%1$sCDN%2$s) integration with Media Library, theme files and WordPress core',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
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
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Caching of pages / posts in memory or on disk or on %1$sCDN%2$s (mirror only)',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			)
			?>
		</li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Caching of (minified) %1$sCSS%2$s and JavaScript in memory, on disk or on %3$sCDN%4$s',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</li>
		<li><?php esc_html_e( 'Caching of database objects in memory or on disk', 'w3-total-cache' ); ?></li>
		<li><?php esc_html_e( 'Caching of objects in memory or on disk', 'w3-total-cache' ); ?></li>
		<li><?php esc_html_e( 'Caching of feeds (site, categories, tags, comments, search results) in memory or on disk', 'w3-total-cache' ); ?></li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Caching of search results pages (i.e. %1$sURI%2$ss with query string variables) in memory or on disk',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Uniform Resource Identifier', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</li>
		<li><?php esc_html_e( 'Minification of posts / pages and feeds', 'w3-total-cache' ); ?></li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Minification (concatenation and white space removal) of inline, external or 3rd party JavaScript / %1$sCSS%2$s with automated updates',
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
		</li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to HTTP ETag Wiki page, 2 closing HTML a tag.
					__(
						'Complete header management including %1$sETags%2$s',
						'w3-total-cache'
					),
					'<a href="' . esc_url( 'http://en.wikipedia.org/wiki/HTTP_ETag' ) . '">',
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
		<li><?php esc_html_e( 'JavaScript embedding group and location management', 'w3-total-cache' ); ?></li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Import post attachments directly into the Media Library (and %1$sCDN%2$s)',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</li>
	</ul>

	<p><?php esc_html_e( 'Your users have less data to download, you can now serve more visitors at once without upgrading your hardware and you don\'t have to change how you do anything; just set it and forget it.', 'w3-total-cache' ); ?></p>

	<h4><?php esc_html_e( 'Who do I thank for all of this?', 'w3-total-cache' ); ?></h4>

	<p><?php esc_html_e( 'It\'s quite difficult to recall all of the innovators that have shared their thoughts, code and experiences in the blogosphere over the years, but here are some names to get you started:', 'w3-total-cache' ); ?></p>

	<ul>
		<li><a href="<?php echo esc_url( 'http://stevesouders.com/' ); ?>" target="_blank">Steve Souders</a></li>
		<li><a href="<?php echo esc_url( 'http://mrclay.org/' ); ?>" target="_blank">Steve Clay</a></li>
		<li><a href="<?php echo esc_url( 'http://wonko.com/' ); ?>" target="_blank">Ryan Grove</a></li>
		<li><a href="<?php echo esc_url( 'http://www.nczonline.net/blog/2009/06/23/loading-javascript-without-blocking/' ); ?>" target="_blank">Nicholas Zakas</a> </li>
		<li><a href="<?php echo esc_url( 'http://rtdean.livejournal.com/' ); ?>" target="_blank">Ryan Dean</a></li>
		<li><a href="<?php echo esc_url( 'http://gravitonic.com/' ); ?>" target="_blank">Andrei Zmievski</a></li>
		<li>George Schlossnagle</li>
		<li>Daniel Cowgill</li>
		<li><a href="<?php echo esc_url( 'http://toys.lerdorf.com/' ); ?>" target="_blank">Rasmus Lerdorf</a></li>
		<li><a href="<?php echo esc_url( 'http://notmysock.org/' ); ?>" target="_blank">Gopal Vijayaraghavan</a></li>
		<li><a href="<?php echo esc_url( 'http://eaccelerator.net/' ); ?>" target="_blank">Bart Vanbraban</a></li>
		<li><a href="<?php echo esc_url( 'http://xcache.lighttpd.net/' ); ?>" target="_blank">mOo</a></li>
	</ul>

	<p><?php esc_html_e( 'Please reach out to all of these people and support their projects if you\'re so inclined.', 'w3-total-cache' ); ?></p>
</div>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
