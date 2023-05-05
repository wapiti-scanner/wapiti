<?php
/**
 * File: PageSpeed_Instructions.php
 *
 * Defines W3TC's recomendations for each PageSpeed metric.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * PageSpeed Instructions Config.
 *
 * @since 2.3.0
 */
class PageSpeed_Instructions {

	/**
	 * Get PageSpeed Instructions Config.
	 *
	 * @since 2.3.0
	 *
	 * @return array
	 */
	public static function get_pagespeed_instructions() {
		$allowed_tags = Util_PageSpeed::get_allowed_tags();
		return array(
			'opportunities' => array(
				'render-blocking-resources'    => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: 1 W3TC plugin name, 2 HTML a tag to W3TC minify JS admin page
								// translators: 3 HTML a tag to W3TC minify CSS admin page.
								esc_html__(
									'%1$s can eliminate render blocking resources. Once Minified, you can defer JS in the %2$s. Render blocking CSS can be eliminated in %3$s using the "Eliminate Render blocking CSS by moving it to HTTP body" (PRO FEATURE).',
									'w3-total-cache'
								),
								'W3 Total Cache',
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#js' ) ) . '" alt="' . esc_attr__( 'Minify JS', 'w3-total-cache' ) . '">' . esc_html__( 'Performance &raquo; Minify &raquo; JS', 'w3-total-cache' ) . '</a> ',
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#css' ) ) . '" alt="' . esc_attr__( 'Minify CSS', 'w3-total-cache' ) . '">' . esc_html__( 'Performance &raquo; Minify &raquo; CSS', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'unused-css-rules'             => array(
					'instructions' =>
						'<p>' . esc_html__( 'Some themes and plugins are loading CSS files or parts of the CSS files on all pages and not only on the pages that should be loading on. For eaxmple if you are using some contact form plugin, there is a chance that the CSS file of that plugin will load not only on the /contact/ page, but on all other pages as well and this is why the unused CSS should be removed.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Open your Chrome browser, go to “Developer Tools”, click on “More Tools” and then “Coverage”.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Coverage will open up. We will see buttons for start capturing coverage, to reload and start capturing coverage and to stop capturing coverage and show results.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'If you have a webpage you want to analyze its code coverage. Load the webpage and click on the o button in the Coverage tab.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'After sometime, a table will show up in the tab with the resources it analyzed, and how much code is used in the webpage. All the files linked in the webpage (css, js) will be listed in the Coverage tab. Clicking on any resource there will open that resource in the Sources panel with a breakdown of Total Bytes and Unused Bytes.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'With this breakdown, we can see how many unused bytes are in our CSS files, so we can manually remove them.', 'w3-total-cache' ) . '</p>',
				),
				'unminified-css'               => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: 1 HTML a tag to W3TC Minify CSS admin page, 2 HTML acronym for CSS, 3 HTML acronym for JS, 4 HTML a tag to W3 API FAQ page containing HTML acronym tag for FAQ.
								esc_html__(
									'On the %1$s tab all of the recommended settings are preset. Use the help button to simplify discovery of your %2$s and %3$s files and groups. Pay close attention to the method and location of your %3$s group embeddings. See the plugin\'s %4$s for more information on usage.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#css' ) ) . '" alt="' . esc_attr__( 'Minify', 'w3-total-cache' ) . '">' . esc_html__( 'Minify', 'w3-total-cache' ) . '</a>',
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">' . esc_html__( 'CSS', 'w3-total-cache' ) . '</acronym>',
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">' . esc_html__( 'JS', 'w3-total-cache' ) . '</acronym>',
								'<a target="_blank" href="https://api.w3-edge.com/v1/redirects/faq/usage" alt="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '"><acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">' . esc_html__( 'FAQ', 'w3-total-cache' ) . '</acronym></a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'unminified-javascript'        => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: 1 HTML a tag to W3TC Minify CSS admin page, 2 HTML acronym for CSS, 3 HTML acronym for JS, 4 HTML a tag to W3 API FAQ page containing HTML acronym tag for FAQ.
								esc_html__(
									'On the %1$s tab all of the recommended settings are preset. Use the help button to simplify discovery of your %2$s and %3$s files and groups. Pay close attention to the method and location of your %3$s group embeddings. See the plugin\'s %4$s for more information on usage.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#js' ) ) . '" alt="' . esc_attr__( 'Minify', 'w3-total-cache' ) . '">' . esc_html__( 'Minify', 'w3-total-cache' ) . '</a>',
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">' . esc_html__( 'CSS', 'w3-total-cache' ) . '</acronym>',
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">' . esc_html__( 'JS', 'w3-total-cache' ) . '</acronym>',
								'<a target="_blank" href="https://api.w3-edge.com/v1/redirects/faq/usage" alt="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '"><acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">' . esc_html__( 'FAQ', 'w3-total-cache' ) . '</acronym></a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'unused-javascript'            => array(
					'instructions' =>
						'<p>' . esc_html__( 'Some themes and plugins are loading JS files or parts of the JS files on all pages and not only on the pages that should be loading on. For eaxmple if you are using some contact form plugin, there is a chance that the JS file of that plugin will load not only on the /contact/ page, but on all other pages as well and this is why the unused JS should be removed.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Open your Chrome browser, go to “Developer Tools”, click on “More Tools” and then “Coverage”.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Coverage will open up. We will see buttons for start capturing coverage, to reload and start capturing coverage and to stop capturing coverage and show results.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'If you have a webpage you want to analyze its code coverage. Load the webpage and click on the o button in the Coverage tab.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'After sometime, a table will show up in the tab with the resources it analyzed, and how much code is used in the webpage. All the files linked in the webpage (css, js) will be listed in the Coverage tab. Clicking on any resource there will open that resource in the Sources panel with a breakdown of Total Bytes and Unused Bytes.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'With this breakdown, we can see how many unused bytes are in our JS files, so we can manually remove them.', 'w3-total-cache' ) . '</p>',
				),
				'uses-responsive-images'       => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: 1 HTML a tag to helpx.adobe.com for optimizing-image-jped-format.
								esc_html__(
									'It\'s important to prepare images before uloading them to the website. This should be done before the Image is uploaded and can be done by using some image optimization tool like %1$s.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( 'https://helpx.adobe.com/photoshop-elements/using/optimizing-images-jpeg-format.html' ) . '">' . esc_html__( 'photoshop', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>
						<p>' . esc_html__( 'Using srcset:', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'The srcset HTML tag provides the browser with variations of an image (including a fallback image) and instructs the browser to use specific images depending on the situation.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Essentially, you create various sizes of your image, and then utilize the srcset tag to define when the images get served. This is useful for responsive design when you have multiple images to deliver across	several devices and dimensions.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'For example, let\'s say you want to send a high-resolution image to only those users that have high-resolution screens, as	determined by the Device pixel ratio (DPR). The code would look like this:', 'w3-total-cache' ) . '</p>
						<code>' . esc_html( '<img srcset="large.jpg 2x, small.jpg 1x" src="small.jpg" alt="' . esc_attr__( 'A single image', 'w3-total-cache' ) . '">' ) . '</code>
						<p>' . esc_html__( 'Use image optimization plugin.', 'w3-total-cache' ) . '</p>',
				),
				'offscreen-images'             => array(
					'instructions' => '<p>' . esc_html__( 'Enable lazy load for images.', 'w3-total-cache' ) . '</p>',
				),
				'uses-optimized-images'        => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 W3TC plugin name, opening HTML a tag to Image Service extension, 3 closing HTML a tag.
							esc_html__(
								'Use %1$s %2$sImage Service%3$s to convert media library images to WebP.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_extensions' ) ) . '" alt="' . esc_attr__( 'W3TC Extensions', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>',
				),
				'modern-image-formats'         => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 W3TC plugin name, opening HTML a tag to Image Service extension, 3 closing HTML a tag.
							esc_html__(
								'Use %1$s %2$sImage Service%3$s to convert media library images to WebP.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_extensions' ) ) . '" alt="' . esc_attr__( 'W3TC Extensions', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>',
				),
				'uses-text-compression'        => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: 1 W3TC plugin name, 2 HTML a tag to kjdev php-ext-brotli.
								esc_html__(
									'Use %1$s Browser Caching - Peformance>Browser Cache - Enable Gzip compression or Brotli compression (Gzip compression is most common and for Brotli compression you need to install %2$s on your server.',
									'w3-total-cache'
								),
								'W3 Total Cache',
								'<a target="_blank" href="' . esc_url( 'https://github.com/kjdev/php-ext-brotli' ) . '">' . esc_html__( 'Brotli extension', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'uses-rel-preconnect'          => array(
					'instructions' =>
						'<p>' . esc_html__( 'Look at the list of third-party resources flagged by Google Page speed and add preconnect or dns-prefetch to their link tags depending on whether the resource is critical or not.', 'w3-total-cache' ) . '</p>
						<ol>
							<li>
								' . esc_html__( 'Add preconnect for critical third-party domains. Out of the list of third-party resources flagged by Google Page speed, identify the critical third-party resources and add the following code to the link tag:', 'w3-total-cache' ) . '
								<code>' . esc_html( '<link rel="preconnect" target="_blank" href="' . esc_url( 'https://third-party-example.com', 'w3-total-cache' ) . '">' ) . '</code>
								' . esc_html__( 'Where "https://third-party-example.com" is the critical third-party domain your page intends to connect to.', 'w3-total-cache' ) . '
							</li>
							<li>
								' . esc_html__( 'Add dns-prefetch for all other third-party domains. For all other third-party scripts, including non-critical ones, add the following code to the link tag:', 'w3-total-cache' ) . '
								<code>' . esc_html( '<link rel="dns-prefetch" target="_blank" href="' . esc_url( 'https://third-party-example.com', 'w3-total-cache' ) . '">' ) . '</code>
								' . esc_html__( 'Where "https://third-party-example.com"	is the domain of the respective third-party resource.', 'w3-total-cache' ) . '
							</li>
						</ol>',
				),
				'server-response-time'         => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to Page Cache setting, 3 closing HTML a tag.
							esc_html__(
								'Use %1$s %2$sPage Caching%3$s (fastest module)',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#page_cache' ) ) . '" alt="' . esc_attr__( 'Page Cache', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>',
				),
				'redirects'                    => array(
					'instructions' =>
						'<p>' . esc_html__( 'When dealing with server-side redirects, we recommend that they be executed via web server configuration as they are often faster than application-level configuration.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Avoid client-side redirects, as much as possible, as they are slower, non-cacheable and may not be supported by browsers by default.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Wherever possible, avoid landing page redirects; especially, the practice of executing separate, individual redirects for reasons such as protocol change, adding www, mobile-specific page, geo-location, and subdomain.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Always redirect to the preferred version of the URL, especially, when redirects are dynamically generated. This helps eliminate unnecessary redirects.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Similarly, remove temporary redirects if not needed anymore.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Remember that combining multiple redirects into a single redirect is the most effective way to improve web performance.', 'w3-total-cache' ) . '</p>',
				),
				'uses-rel-preload'             => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 W3TC plugin name.
							esc_html__(
								'JS and CSS - Use HTTP2/Push for %1$s Minified files',
								'w3-total-cache'
							),
							'W3 Total Cache'
						) . '</p>
						<p>' . esc_html__( 'Preload fonts hosted on the server: ', 'w3-total-cache' ) . '<code>' . esc_html( '<link rel="preload" target="_blank" href="fontname" as="font" type="font/format" crossorigin>' ) . '</code></p>',
				),
				'efficient-animated-content'   => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 W3TC plugin name, opening HTML a tag to Image Service extension, 3 closing HTML a tag.
							esc_html__(
								'Use %1$s %2$sImage Service%3$s to convert media library images to WebP.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_extensions' ) ) . '" alt="' . esc_attr__( 'W3TC Extensions', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>',
				),
				'duplicated-javascript'        => array(
					'instructions' =>
						'<p>' . esc_html__( 'Incorporate good site building practices into your development workflow to ensure you avoid duplication of JavaScript modules in the first place.', 'w3-total-cache' ) . '</p>
						<p>' .
						wp_kses(
							sprintf(
								// translators: 1 HTML a tag to Zillow Webpack-Stats-Duplicates.
								esc_html__(
									'To fix this audit, use a tool like %1$s to identify duplicate modules',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( 'https://github.com/zillow/webpack-stats-duplicates' ) . '">' . esc_html__( 'webpack-stats-duplicates', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'legacy-javascript'            => array(
					'instructions' =>
						'<p>' . esc_html__( 'One way to deal with this issue is to load polyfills, only when needed, which can provide feature-detection support at JavaScript runtime. However, it is often very difficult to implement in practice.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Implement modern feature-detection using ', 'w3-total-cache' ) . '<code>' . esc_html( '<script type="module">' ) . '</code>' . esc_html__( ' and ', 'w3-total-cache' ) . '<code>' . esc_html( '<script nomodule>' ) . '</code>.</p>
						<p>' . esc_html__( 'Every browser that supports ', 'w3-total-cache' ) . '<code>' . esc_html( '<script type="module">' ) . '</code>' . esc_html__( ' also supports most of the ES6 features. This lets you load regular JavaScript files with ES6 features, knowing that the browser can handle it.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'For browsers that don\'t support ', 'w3-total-cache' ) . '<code>' . esc_html( '<script type="module">' ) . '</code>' . esc_html__( ' you can use the translated ES5 code instead. In this manner, you are always serving modern code to modern browsers.', 'w3-total-cache' ) . '</p>
						<p>' .
						wp_kses(
							sprintf(
								// translators: 1 HTML a tag to philipwalton.com for deplying-es2015-code-in-production-today.
								esc_html__(
									'Learn more about implementing this technique %1$s.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( 'https://philipwalton.com/articles/deploying-es2015-code-in-production-today/' ) . '">' . esc_html__( 'here', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'preload-lcp-image'            => array(
					'instructions' => '<p>' . esc_html__( 'Enable lazy load for images.', 'w3-total-cache' ) . '</p>',
				),
				'total-byte-weight'            => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to Minify setting, 3 closing HTML a tag.
							esc_html__(
								'Deffer or async the JS (Select  Non blocking using Defer or  Non blocking using async Embed method in %1$s %2$sMinify%3$s options before head and after body)',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#minify' ) ) . '" alt="' . esc_attr__( 'Minify', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>
						<p>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to CSS Minify settings, 3 closing HTML a tag,
							// translators: 4 opening html a tagl to JS Minify settings, 5 closing HTML a tag.
							esc_html__(
								'Compress your HTML, CSS, and JavaScript files and minify your CSS and JavaScript to ensure your text-based resources are as small as they can be. Use the %1$s Minify %2$sJS%3$s and %4$sCSS%5$s features to accomplish this.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#css' ) ) . '" alt="' . esc_attr__( 'Minify CSS', 'w3-total-cache' ) . '">',
							'</a>',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#js' ) ) . '" alt="' . esc_attr__( 'Minify JS', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>
						<p>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to W3TC extensions, 3 closing HTML a tag.
							esc_html__(
								'Optimize your image delivery by sizing them properly and compressing them for smaller sizes. Use Webp conversion via the %1$s %2$sImage Service%3$s extension.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_extensions' ) ) . '" alt="' . esc_attr__( 'W3TC Extensions', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>
						<p>' . sprintf(
							// translators: 1 opening HTML a tag to Browser Caching setting, 2 closing HTML a tag.
							esc_html__(
								'Use %1$sBrowser Caching%2$s for static files and HTML  - 1 year for static files 1 hor for html',
								'w3-total-cache'
							),
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#browser_cache' ) ) . '" alt="' . esc_attr__( 'Browser Cache', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>',
				),
				'dom-size'                     => array(
					'instructions' =>
						'<p>' . esc_html__( 'Without completely redesigning your web page from scratch, typically you cannot resolve this warning. Understand that this warning is significant and if you get it for more than one or two pages in your site, you should consider:', 'w3-total-cache' ) . '</p>
						<ol>
							<li>' . esc_html__( 'Reducing the amount of widgets / sections within your web pages or page layouts', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Using a simpler web page builder as many page builders add a lot of code bloat', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Using a different theme', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Using a different slider', 'w3-total-cache' ) . '</li>
						</ol>',
				),
				'user-timings'                 => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: HTML a tag to developer.mozilla.org for User_Timing_API.
								esc_html__(
									'The %1$s gives you a way to measure your app\'s JavaScript performance.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( 'https://developer.mozilla.org/docs/Web/API/User_Timing_API' ) . '">' . esc_html__( 'User Timing API', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>
						<p>' . esc_html__( 'You do that by inserting API calls in your JavaScript and then extracting detailed timing data that you can use to optimize your code.', 'w3-total-cache' ) . '</p>
						<p>' . wp_kses(
							sprintf(
								// translators: 1 HTML a tag to developer.chrome.com for devtools/evaluate-performance/reference.
								esc_html__(
									'You can access those data from JavaScript using the API or by viewing them on your %1$s.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( 'https://developer.chrome.com/docs/devtools/evaluate-performance/reference/' ) . '">' . esc_html__( 'Chrome DevTools Timeline Recordings', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'bootup-time'                  => array(
					'instructions' =>
						'<p>' . wp_kses(
							sprintf(
								// translators: 1 HTML a tag to W3TC Minify JS admin page, 2 HTML acronym for CSS, 3 HTML acronym for JS, 4 HTML a tag to W3 API FAQ page containing HTML acronym tag for FAQ.
								esc_html__(
									'On the %1$s tab all of the recommended settings are preset. Use the help button to simplify discovery of your %2$s and %3$s files and groups. Pay close attention to the method and location of your %3$s group embeddings. See the plugin\'s %4$s for more information on usage.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#js' ) ) . '" alt="' . esc_attr__( 'Minify', 'w3-total-cache' ) . '">' . esc_html__( 'Minify', 'w3-total-cache' ) . '</a>',
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">' . esc_html__( 'CSS', 'w3-total-cache' ) . '</acronym>',
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">' . esc_html__( 'JS', 'w3-total-cache' ) . '</acronym>',
								'<a target="_blank" href="https://api.w3-edge.com/v1/redirects/faq/usage" alt="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '"><acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">' . esc_html__( 'FAQ', 'w3-total-cache' ) . '</acronym></a>'
							),
							$allowed_tags
						) . '</p>',
				),
				'mainthread-work-breakdown'    => array(
					'instructions' =>
						'<p>' . esc_html__( 'Optimizing third-party JavaScript', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Review your website\'s third-party code and remove the ones	that aren\'t adding any value to your website.', 'w3-total-cache' ) . '</p>
						<p><a target="_blank" href="' . esc_url( 'https://web.dev/debounce-your-input-handlers/' ) . '">' . esc_html__( 'Debouncing your input handlers', 'w3-total-cache' ) . '</a></p>
						<p>' . esc_html__( 'Avoid using long-running input handlers (which may block scrolling) and do not make style changes in input handlers (which is likely to cause repainting of pixels).', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Debouncing your input handlers helps solve both of the above problems.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Delay 3rd-party JS', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Reducing JavaScript execution time', 'w3-total-cache' ) . '</p>
						<p>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to Minify JS settings, 3 closing HTML a tag,
							// translators: 4 opening HTML a tag to CDN setting, 5 closing HTML a tag.
							esc_html__(
								'Reduce your JavaScript payload by implementing code splitting, minifying and compressing your JavaScript code, removing unused code, and following the PRPL pattern. (Use %1$s Minify for %2$sJS%3$s and compression.) Use %4$sCDN%5$s and HTTP2 Push if available on server.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#js' ) ) . '" alt="' . esc_attr__( 'Minify JS', 'w3-total-cache' ) . '">',
							'</a>',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#cdn' ) ) . '" alt="' . esc_attr__( 'CDN', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>
						<p>' . esc_html__( 'Reducing CSS parsing time', 'w3-total-cache' ) . '</p>
						<p>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to Minify CSS settings, 3 closing HTML a tag,
							// translators: 4 opening HTML a tag to CDN setting, 5 closing HTML a tag.
							esc_html__(
								'Reduce the time spent parsing CSS by minifying, or deferring non-critical CSS, or removing unused CSS. (Use %1$s Minify for %2$sCSS%3$s and compression.) Use %4$sCDN%5$s and HTTP2 Push if available on server.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#css' ) ) . '" alt="' . esc_attr__( 'Minify CSS', 'w3-total-cache' ) . '">',
							'</a>',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#cdn' ) ) . '" alt="' . esc_attr__( 'CDN', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</p>
						<p><a target="_blank" href="' . esc_url( 'https://developers.google.com/web/fundamentals/performance/rendering/stick-to-compositor-only-properties-and-manage-layer-count' ) . '">' . esc_html__( 'Only using compositor properties', 'w3-total-cache' ) . '</a></p>
						<p>' . esc_html__( 'Stick to using compositor properties to keep events away from the main-thread. Compositor properties are run on a separate compositor thread, freeing the main-thread for longer and improving your page load performance.', 'w3-total-cache' ) . '</p>',
				),
				'third-party-summary'          => array(
					'instructions' =>
						'<ol>
							<li>' . esc_html__( 'Find Slow Third-Party-Code', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Lazy Load YouTube Videos', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Host Google Fonts Locally', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Host Google Analytics Locally', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Host Facebook Pixel Locally', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Host Gravatars Locally', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Delay Third-Party JavaScript', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Defer Parsing Of JavaScript', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Prefetch Or Preconnect Third-Party Scripts', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Avoid Google AdSense And Maps', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Don\'t Overtrack In Google Tag Manager', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Replace Embeds With Screenshots', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Use A Lightweight Social Sharing Plugin', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Use Cloudflare Workers', 'w3-total-cache' ) . '</li>
						</ol>',
				),
				'third-party-facades'          => array(
					'instructions' => '<p>' . esc_html__( 'Preload - Lazyload embeded videos.', 'w3-total-cache' ) . '</p>',
				),
				'lcp-lazy-loaded'              => array(
					'instructions' =>
						'<p>' . esc_html__( 'Don\'t lazy load images that appear "above the fold" just use a standard ', 'w3-total-cache' ) . esc_html( '<img>' ) . esc_html__( ' or ', 'w3-total-cache' ) . esc_html( '<picture>' ) . esc_html__( '	element.', 'w3-total-cache' ) . '</p>
						<p>' . sprintf(
							// translators: 1 W3TC plugin name.
							esc_html__(
								'Exclude the image from being lazy-loaded if the %1$s Lazy load is enabled in Performance &raquo; User Experience &raquo; Exclude words.',
								'w3-total-cache'
							),
							'W3 Total Cache'
						) . '</p>',
				),
				'uses-passive-event-listeners' => array(
					'instructions' =>
						'<p>' . esc_html__( 'Add a passive flag to every event listener that Lighthouse identified.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'If you\'re only supporting browsers that have passive event listener support, just add the flag.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'For example:', 'w3-total-cache' ) . '</p>
						<code>' . esc_html( 'document.addEventListener("touchstart", onTouchStart, {passive: true});' ) . '</code>
						<p>' . esc_html__( 'If you\'re supporting older browsers that don\'t support passive event listeners, you\'ll need to use feature detection or a polyfill. See the Feature Detection section of the WICG Passive event listeners explainer document for more information.', 'w3-total-cache' ) . '</p>',
				),
				'no-document-write'            => array(
					'instructions' =>
						'<p>' . esc_html__( 'You can fix this audit by preferably eliminating document.write() altogether, wherever possible.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Avoiding the use of document.write() should ideally be built into your development workflow so that your production website is optimized for web performance from the beginning.', 'w3-total-cache' ) . '</p>
						<p>' . sprintf(
							// translators: 1 W3TC plugin name.
							esc_html__(
								'Using %1$s JS Minify and deferring or using async may also help.',
								'w3-total-cache'
							),
							'W3 Total Cache'
						) . '</p>',
				),
				'non-composited-animations'    => array(
					'instructions' =>
						'<p><a target="_blank" href="' . esc_url( 'https://developers.google.com/web/fundamentals/performance/rendering/stick-to-compositor-only-properties-and-manage-layer-count' ) . '">' . esc_html__( 'Only using compositor properties:', 'w3-total-cache' ) . '</a></p>
						<p>' . esc_html__( 'Stick to using compositor properties to keep events away from the main-thread. Compositor properties are run on a separate compositor thread, freeing the main-thread for longer and improving your page load performance.', 'w3-total-cache' ) . '</p>',
				),
				'unsized-images'               => array(
					'instructions' =>
						'<p>' . esc_html__( 'To fix this audit, simply specify, both, the width and height for your webpage\'s image and video elements. This ensures that the correct spacing is used for images and videos.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'For example:', 'w3-total-cache' ) . '</p>
						<code>' . esc_html( '<img src="image.jpg" width="640" height="360" alt="image">' ) . '</code>
						<p>' . esc_html__( 'Where width and height have been declared as 640 and 360 pixels respectively.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Note that modern browsers automatically calculate the aspect ratio for an image/video based on the declared width and height attributes.', 'w3-total-cache' ) . '</p>',
				),
				'viewport'                     => array(
					'instructions' =>
						'<p>' . esc_html__( 'Use the "viewport" <meta> tag to control the viewport\'s size and shape form mobile friendly website:', 'w3-total-cache' ) . '</p>
						<code>' . esc_html( '<meta name="viewport" content="width=device-width, initial-scale=1">' ) . '</code>
						<p>' .
						wp_kses(
							sprintf(
								// translators: 1 HTML a tag to developer.mozilla.org for documentation on viewport_meta_tag.
								esc_html__(
									'More details %1$s.',
									'w3-total-cache'
								),
								'<a target="_blank" href="' . esc_url( 'https://developer.mozilla.org/en-US/docs/Web/HTML/Viewport_meta_tag' ) . '">' . esc_html__( 'here', 'w3-total-cache' ) . '</a>'
							),
							$allowed_tags
						) . '</p>',
				),
			),
			'diagnostics'   => array(
				'font-display'                     => array(
					'instructions' =>
						'<p>' . esc_html__( 'It\'s advisable to host the fonts on the server instead of using Google CDN', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Preload fonts with a plugin or manually:', 'w3-total-cache' ) . '</p>
						<br/>
						<code>' . esc_html( '<link rel="preload" target="_blank" href="/webfontname" as="font" type="font/format" crossorigin>' ) . '</code>
						<br/>
						<p>' . esc_html__( 'Use font-display atribute: The font-display attribute determines how the font is displayed during your page load, based on whether it has been downloaded and is ready for use.', 'w3-total-cache' ) . '</p>',
				),
				'first-contentful-paint-3g'        => array(
					'instructions' =>
						'<p>' . esc_html__( 'Enable Page Cache using the fastest engine.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'What it represents: How much is visible at a time during load.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'Lighthouse Performance score weighting: 10%', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'What it measures: The Speed Index is the average time at which visible parts of the page are displayed.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'How it\'s measured: Lighthouse\'s Speed Index measurement comes from a node module called Speedline.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'In order for content to be displayed to the user, the browser must first download, parse, and process all external stylesheets it encounters before it can display or render any content to a user\'s screen.', 'w3-total-cache' ) . '</p>
						<p>' . esc_html__( 'The fastest way to bypass the delay of external resources is to use in-line styles for above-the-fold content.', 'w3-total-cache' ) . '</p>',
				),
				'uses-long-cache-ttl'              => array(
					'instructions' =>
						'<p>' . sprintf(
							// translators: 1 opening HTML a tag to Browswer Cache settings, 2 closing HTML a tag, 3 W3TC plugin name.
							esc_html__(
								'Use %1$sBrowser Caching%2$s in %3$s and set the Expires header and cache control header for static files and HTML.',
								'w3-total-cache'
							),
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#browser_cache' ) ) . '" alt="' . esc_attr__( 'Browser Cache', 'w3-total-cache' ) . '">',
							'</a>',
							'W3 Total Cache'
						) . '</p>
						<p>' . esc_html__( 'Use default values for best results', 'w3-total-cache' ) . '</p>',
				),
				'critical-request-chains'          => array(
					'instructions' => '<p>' . esc_html__( 'Eliminate Render Blocking CSS and apply asynchronous loading where applicable. Additionally, image optimization by way of resizing, lazy loaidng, and webp conversion can impact this metric as well.', 'w3-total-cache' ) . '</p>',
				),
				'resource-summary'                 => array(
					'instructions' =>
						'<p>Actions that can help:</p>
						<ul>
							<li>' . esc_html__( 'Avoid multiple page redirects.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Combine images using CSS sprites.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Remove unnecessary third-party scripts.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Compress your text resources.', 'w3-total-cache' ) . '</li>
						</ul>',
				),
				'largest-contentful-paint-element' => array(
					'instructions' =>
						'<p>' . esc_html__( 'How To Fix Poor LCP', 'w3-total-cache' ) . '</p>
						<br/>
						<p>' . esc_html__( 'If the cause is slow server response time:', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Optimize your server.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Route users to a nearby CDN.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Cache assets.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Serve HTML pages cache-first.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Establish third-party connections early.', 'w3-total-cache' ) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'If the cause is render-blocking JavaScript and CSS:', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Minify CSS.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Defer non-critical CSS.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Inline critical CSS.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Minify and compress JavaScript files.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Defer unused JavaScript.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Minimize unused polyfills.', 'w3-total-cache' ) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'If the cause is resource load times:', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Optimize and compress images.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Preload important resources.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Compress text files.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Deliver different assets based on the network connection (adaptive serving).', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Cache assets using a service worker.', 'w3-total-cache' ) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'If the cause is client-side rendering:', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Minimize critical JavaScript.', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Use another rendering strategy.', 'w3-total-cache' ) . '</li>
						</ul>
						<br/>
						<p>W3 Total Cache ' . esc_html__( 'Features that will help performace of the above:', 'w3-total-cache' ) . '</p>
						<ul>
							<li><a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#minify' ) ) . '" alt="' . esc_attr__( 'Minify', 'w3-total-cache' ) . '">' . esc_html__( 'Minify', 'w3-total-cache' ) . '</a></li>
							<li><a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#page_cache' ) ) . '" alt="' . esc_attr__( 'Page Cache', 'w3-total-cache' ) . '">' . esc_html__( 'Page Cache', 'w3-total-cache' ) . '</a></li>
							<li><a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#browser_cache' ) ) . '" alt="' . esc_attr__( 'Browser Cache', 'w3-total-cache' ) . '">' . esc_html__( 'Browser Cache', 'w3-total-cache' ) . '</a></li>
							<li><a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#cdn' ) ) . '" alt="' . esc_attr__( 'CDN', 'w3-total-cache' ) . '">' . esc_html__( 'CDN', 'w3-total-cache' ) . '</a></li>
						</ul>',
				),
				'layout-shift-elements'            => array(
					'instructions' =>
						'<p>' . esc_html__( 'Without completely redesigning your web page from scratch, typically you cannot resolve this warning.  Understand that this warning is significant and if you get it for more than one or two pages in your site, you should consider:', 'w3-total-cache' ) . '</p>
						<br/>
						<ul>
							<li>' . esc_html__( 'Reducing the amount of widgets / sections within your web pages or page layouts', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Using a simpler web page builder as many page builders add a lot of code bloat', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Using a different theme', 'w3-total-cache' ) . '</li>
							<li>' . esc_html__( 'Using a different slider', 'w3-total-cache' ) . '</li>
						</ul>',
				),
				'long-tasks'                       => array(
					'instructions' =>
						'<p>' . esc_html__( 'Optimizing third-party JavaScript', 'w3-total-cache' ) . '</p>
						<br/>
						<ul>
							<li>' . esc_html__( 'Review your website\'s third-party code and remove the ones that aren\'t adding any value to your website.', 'w3-total-cache' ) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'Debouncing your input handlers', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Avoid using long-running input handlers (which may block scrolling) and do not make style changes in input handlers (which is likely to cause repainting of pixels).', 'w3-total-cache' ) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'Debouncing your input handlers helps solve both of the above problems.', 'w3-total-cache' ) . '</p>
						<br/>
						<p>' . esc_html__( 'Delay 3rd-party JS', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Reducing JavaScript execution time', 'w3-total-cache' ) . '</li>
							<li>' . sprintf(
								// translators: 1 W3TC plugin name, 2 opening HTML a tag to CDN setting, 3 closing HTML a tag,
								// translators: 4 opening HTML a tag to CDN setting, 5 closing HTML a tag.
								esc_html__(
									'Reduce your JavaScript payload by implementing code splitting, minifying and compressing your JavaScript code, removing unused code, and following the PRPL pattern. (Use %1$s %2$sMinify for JS%3$s and compression.) Use %4$sCDN%5$s and HTTP2 Push if available on server.',
									'w3-total-cache'
								),
								'W3 Total Cache',
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#js' ) ) . '" alt="' . esc_attr__( 'Minify JS', 'w3-total-cache' ) . '">',
								'</a>',
								'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#cdn' ) ) . '" alt="' . esc_attr__( 'CDN', 'w3-total-cache' ) . '">',
								'</a>'
							) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'Only using compositor properties', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Stick to using compositor properties to keep events away from the main-thread. Compositor properties are run on a separate compositor thread, freeing the main-thread for longer and improving your page load performance.', 'w3-total-cache' ) . '</li>
						</ul>
						</ul>
						<br/>
						<p>' . esc_html__( 'Reducing CSS parsing time', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . sprintf(
							// translators: 1 W3TC plugin name, 2 opening HTML a tag to Minify CSS settings, 3 closing HTML a tag,
							// translators: 4 opening HTML a tag to CDN setting, 5 closing HTML a tag.
							esc_html__(
								'Reduce the time spent parsing CSS by minifying, or deferring non-critical CSS, or removing unused CSS. (Use %1$s %2$sMinify for CSS%3$s and compression.) Use %4$sCDN%5$s and HTTP2 Push if available on server.',
								'w3-total-cache'
							),
							'W3 Total Cache',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_minify#css' ) ) . '" alt="' . esc_attr__( 'Minify CSS', 'w3-total-cache' ) . '">',
							'</a>',
							'<a target="_blank" href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_general#cdn' ) ) . '" alt="' . esc_attr__( 'CDN', 'w3-total-cache' ) . '">',
							'</a>'
						) . '</li>
						</ul>
						<br/>
						<p>' . esc_html__( 'Only using compositor properties', 'w3-total-cache' ) . '</p>
						<ul>
							<li>' . esc_html__( 'Stick to using compositor properties to keep events away from the main-thread. Compositor properties are run on a separate compositor thread, freeing the main-thread for longer and improving your page load performance.', 'w3-total-cache' ) . '</li>
						</ul>',
				),
			),
		);
	}
}
