<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Crowdsignal (PollDaddy) shortcode.
 *
 * Formats:
 * [polldaddy type="iframe" survey="EB151947E5950FCF" height="auto" domain="jeherve" id="a-survey-with-branches"]
 * [crowdsignal type="iframe" survey="EB151947E5950FCF" height="auto" domain="jeherve" id="a-survey-with-branches"]
 * https://polldaddy.com/poll/7910844/
 * https://jeherve.survey.fm/a-survey
 * https://jeherve.survey.fm/a-survey-with-branches
 * [crowdsignal type="iframe" survey="7676FB1FF2B56CE9" height="auto" domain="jeherve" id="a-survey"]
 * [crowdsignal survey="7676FB1FF2B56CE9"]
 * [polldaddy survey="7676FB1FF2B56CE9"]
 * [crowdsignal poll=9541291]
 * [crowdsignal poll=9541291 type=slider]
 * [crowdsignal rating=8755352]
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Constants;

// Keep compatibility with the PollDaddy plugin.
if (
	! class_exists( 'CrowdsignalShortcode' )
	&& ! class_exists( 'PolldaddyShortcode' )
) {
	/**
	 * Class wrapper for Crowdsignal shortcodes
	 */
	class CrowdsignalShortcode {

		/**
		 * Should the Crowdsignal JavaScript be added to the page?
		 *
		 * @var bool
		 */
		private static $add_script = false;

		/**
		 * Array of Polls / Surveys present on the page, and that need to be added.
		 *
		 * @var bool|array
		 */
		private static $scripts = false;

		/**
		 * Add all the actions & register the shortcode.
		 */
		public function __construct() {
			add_action( 'init', array( $this, 'register_scripts' ) );

			add_shortcode( 'crowdsignal', array( $this, 'crowdsignal_shortcode' ) );
			add_shortcode( 'polldaddy', array( $this, 'polldaddy_shortcode' ) );

			add_filter( 'pre_kses', array( $this, 'crowdsignal_embed_to_shortcode' ) );
			add_action( 'infinite_scroll_render', array( $this, 'crowdsignal_shortcode_infinite' ), 11 );
		}

		/**
		 * Register scripts that may be enqueued later on by the shortcode.
		 */
		public static function register_scripts() {
			wp_register_script(
				'crowdsignal-shortcode',
				Assets::get_file_url_for_environment( '_inc/build/crowdsignal-shortcode.min.js', '_inc/crowdsignal-shortcode.js' ),
				array(),
				JETPACK__VERSION,
				true
			);
			wp_register_script(
				'crowdsignal-survey',
				Assets::get_file_url_for_environment( '_inc/build/crowdsignal-survey.min.js', '_inc/crowdsignal-survey.js' ),
				array(),
				JETPACK__VERSION,
				true
			);
			wp_register_script(
				'crowdsignal-rating',
				'https://polldaddy.com/js/rating/rating.js',
				array(),
				JETPACK__VERSION,
				true
			);
		}

		/**
		 * JavaScript code for a specific survey / poll.
		 *
		 * @param array  $settings Array of information about a survey / poll.
		 * @param string $survey_link HTML link tag for a specific survey or poll.
		 * @param string $survey_url  Link to the survey or poll.
		 */
		private function get_async_code( array $settings, $survey_link, $survey_url ) {
			wp_enqueue_script( 'crowdsignal-survey' );

			if ( 'button' === $settings['type'] ) {
				$placeholder = sprintf(
					'<a class="cs-embed pd-embed" href="%1$s" data-settings="%2$s">%3$s</a>',
					esc_url( $survey_url ),
					esc_attr( wp_json_encode( $settings ) ),
					esc_html( $settings['title'] )
				);
			} else {
				$placeholder = sprintf(
					'<div class="cs-embed pd-embed" data-settings="%1$s"></div><noscript>%2$s</noscript>',
					esc_attr( wp_json_encode( $settings ) ),
					$survey_link
				);
			}

			return $placeholder;
		}

		/**
		 * Crowdsignal Poll Embed script - transforms code that looks like that:
		 * <script type="text/javascript" charset="utf-8" async src="http://static.polldaddy.com/p/123456.js"></script>
		 * <noscript><a href="http://polldaddy.com/poll/123456/">What is your favourite color?</a></noscript>
		 * into the [crowdsignal poll=...] shortcode format
		 *
		 * @param string $content Post content.
		 */
		public function crowdsignal_embed_to_shortcode( $content ) {

			if ( ! is_string( $content ) || false === strpos( $content, 'polldaddy.com/p/' ) ) {
				return $content;
			}

			$regexes = array();

			$regexes[] = '#<script[^>]+?src="https?://(secure|static)\.polldaddy\.com/p/([0-9]+)\.js"[^>]*+>\s*?</script>\r?\n?(<noscript>.*?</noscript>)?#i';

			$regexes[] = '#&lt;script(?:[^&]|&(?!gt;))+?src="https?://(secure|static)\.polldaddy\.com/p/([0-9]+)\.js"(?:[^&]|&(?!gt;))*+&gt;\s*?&lt;/script&gt;\r?\n?(&lt;noscript&gt;.*?&lt;/noscript&gt;)?#i';

			foreach ( $regexes as $regex ) {
				if ( ! preg_match_all( $regex, $content, $matches, PREG_SET_ORDER ) ) {
					continue;
				}

				foreach ( $matches as $match ) {
					if ( ! isset( $match[2] ) ) {
						continue;
					}

					$id = (int) $match[2];

					if ( $id > 0 ) {
						$content = str_replace( $match[0], " [crowdsignal poll=$id]", $content );
						/** This action is documented in modules/shortcodes/youtube.php */
						do_action( 'jetpack_embed_to_shortcode', 'crowdsignal', $id );
					}
				}
			}

			return $content;
		}

		/**
		 * Support for legacy Polldaddy shortcode.
		 *
		 * @param array $atts Shortcode attributes.
		 */
		public function polldaddy_shortcode( $atts ) {
			if ( ! is_array( $atts ) ) {
				return '<!-- Polldaddy shortcode passed invalid attributes -->';
			}

			$atts['site'] = 'polldaddy.com';
			return $this->crowdsignal_shortcode( $atts );
		}

		/**
		 * Shortcode for Crowdsignal
		 * [crowdsignal poll|survey|rating="123456"]
		 *
		 * @param array $atts Shortcode attributes.
		 */
		public function crowdsignal_shortcode( $atts ) {
			global $post;
			global $content_width;

			if ( ! is_array( $atts ) ) {
				return '<!-- Crowdsignal shortcode passed invalid attributes -->';
			}

			$attributes = shortcode_atts(
				array(
					'survey'     => null,
					'link_text'  => esc_html__( 'Take Our Survey', 'jetpack' ),
					'poll'       => 'empty',
					'rating'     => 'empty',
					'unique_id'  => null,
					'item_id'    => null,
					'title'      => null,
					'permalink'  => null,
					'cb'         => 0, // cache buster. Helps with testing.
					'type'       => 'button',
					'body'       => '',
					'button'     => '',
					'text_color' => '000000',
					'back_color' => 'FFFFFF',
					'align'      => '',
					'style'      => '',
					'width'      => $content_width,
					'height'     => floor( $content_width * 3 / 4 ),
					'delay'      => 100,
					'visit'      => 'single',
					'domain'     => '',
					'id'         => '',
					'site'       => 'crowdsignal.com',
				),
				$atts,
				'crowdsignal'
			);

			$inline = ! in_the_loop()
				&& ! Constants::is_defined( 'TESTING_IN_JETPACK' );

			$no_script       = false;
			$infinite_scroll = false;

			if ( is_home() && current_theme_supports( 'infinite-scroll' ) ) {
				$infinite_scroll = true;
			}

			if ( function_exists( 'get_option' ) && get_option( 'polldaddy_load_poll_inline' ) ) {
				$inline = true;
			}

			if ( is_feed() || ( defined( 'DOING_AJAX' ) && ! $infinite_scroll ) ) {
				$no_script = false;
			}

			self::$add_script = $infinite_scroll;

			/*
			 * Rating embed.
			 */
			if ( (int) $attributes['rating'] > 0 && ! $no_script ) {

				if ( empty( $attributes['unique_id'] ) ) {
					$attributes['unique_id'] = is_page() ? 'wp-page-' . $post->ID : 'wp-post-' . $post->ID;
				}

				if ( empty( $attributes['item_id'] ) ) {
					$attributes['item_id'] = is_page() ? '_page_' . $post->ID : '_post_' . $post->ID;
				}

				if ( empty( $attributes['title'] ) ) {
					/** This filter is documented in core/src/wp-includes/general-template.php */
					$attributes['title'] = apply_filters( 'wp_title', $post->post_title, '', '' );
				}

				if ( empty( $attributes['permalink'] ) ) {
					$attributes['permalink'] = get_permalink( $post->ID );
				}

				$rating    = (int) $attributes['rating'];
				$unique_id = preg_replace( '/[^\-_a-z0-9]/i', '', wp_strip_all_tags( $attributes['unique_id'] ) );
				$item_id   = wp_strip_all_tags( $attributes['item_id'] );
				$item_id   = preg_replace( '/[^_a-z0-9]/i', '', $item_id );

				$settings = wp_json_encode(
					array(
						'id'        => $rating,
						'unique_id' => $unique_id,
						'title'     => rawurlencode( trim( $attributes['title'] ) ),
						'permalink' => esc_url( $attributes['permalink'] ),
						'item_id'   => $item_id,
					)
				);

				$item_id = esc_js( $item_id );

				if (
					class_exists( 'Jetpack_AMP_Support' )
					&& Jetpack_AMP_Support::is_amp_request()
				) {
					return sprintf(
						'<a href="%s" target="_blank">%s</a>',
						esc_url( $attributes['permalink'] ),
						esc_html( trim( $attributes['title'] ) )
					);
				} elseif ( $inline ) {
					$rating_js  = "<!--//--><![CDATA[//><!--\n";
					$rating_js .= "PDRTJS_settings_{$rating}{$item_id}={$settings};";
					$rating_js .= "\n//--><!]]>";

					wp_enqueue_script( 'crowdsignal-rating' );
					wp_add_inline_script(
						'crowdsignal-rating',
						$rating_js,
						'before'
					);

					return sprintf(
						'<div class="cs-rating pd-rating" id="pd_rating_holder_%1$d%2$s"></div>',
						absint( $rating ),
						esc_attr( $item_id )
					);
				} else {
					if ( false === self::$scripts ) {
						self::$scripts = array();
					}

					$data = array(
						'id'       => $rating,
						'item_id'  => $item_id,
						'settings' => $settings,
					);

					self::$scripts['rating'][] = $data;

					add_action( 'wp_footer', array( $this, 'generate_scripts' ) );

					if ( $infinite_scroll ) {
						return sprintf(
							'<div class="cs-rating pd-rating" id="pd_rating_holder_%1$d%2$s" data-settings="%3$s"></div>',
							absint( $rating ),
							esc_attr( $item_id ),
							esc_attr( wp_json_encode( $data ) )
						);
					} else {
						return sprintf(
							'<div class="cs-rating pd-rating" id="pd_rating_holder_%1$d%2$s"></div>',
							absint( $rating ),
							esc_attr( $item_id )
						);
					}
				}
			} elseif ( (int) $attributes['poll'] > 0 ) {
				/*
				 * Poll embed.
				 */

				if ( empty( $attributes['title'] ) ) {
					$attributes['title'] = esc_html__( 'Take Our Poll', 'jetpack' );
				}

				$poll = (int) $attributes['poll'];

				if ( 'crowdsignal.com' === $attributes['site'] ) {
					$poll_url = sprintf( 'https://poll.fm/%d', $poll );
				} else {
					$poll_url = sprintf( 'https://polldaddy.com/p/%d', $poll );
				}

				$poll_js   = sprintf( 'https://secure.polldaddy.com/p/%d.js', $poll );
				$poll_link = sprintf(
					'<a href="%s" target="_blank">%s</a>',
					esc_url( $poll_url ),
					esc_html( $attributes['title'] )
				);

				if (
					$no_script
					|| ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() )
				) {
					return $poll_link;
				} elseif ( 'slider' === $attributes['type'] && ! $inline ) { // Slider poll.
					if ( ! in_array(
						$attributes['visit'],
						array( 'single', 'multiple' ),
						true
					) ) {
						$attributes['visit'] = 'single';
					}

					$settings = array(
						'type'  => 'slider',
						'embed' => 'poll',
						'delay' => (int) $attributes['delay'],
						'visit' => $attributes['visit'],
						'id'    => (int) $poll,
						'site'  => $attributes['site'],
					);

					return $this->get_async_code( $settings, $poll_link, $poll_url );
				} else {
					if ( 1 === $attributes['cb'] ) {
						$attributes['cb'] = '?cb=' . time();
					} else {
						$attributes['cb'] = false;
					}
					$margins = '';
					$float   = '';

					if ( in_array(
						$attributes['align'],
						array( 'right', 'left' ),
						true
					) ) {
						$float = sprintf( 'float: %s;', $attributes['align'] );

						if ( 'left' === $attributes['align'] ) {
							$margins = 'margin: 0px 10px 0px 0px;';
						} elseif ( 'right' === $attributes['align'] ) {
							$margins = 'margin: 0px 0px 0px 10px';
						}
					}

					/*
					 * Force the normal style embed on single posts/pages
					 * otherwise it's not rendered on infinite scroll themed blogs
					 * ('infinite_scroll_render' isn't fired)
					 */
					if ( is_singular() ) {
						$inline = true;
					}

					if ( false === $attributes['cb'] && ! $inline ) {
						if ( false === self::$scripts ) {
							self::$scripts = array();
						}

						$data = array( 'url' => $poll_js );

						self::$scripts['poll'][ (int) $poll ] = $data;

						add_action( 'wp_footer', array( $this, 'generate_scripts' ) );

						wp_enqueue_script( 'crowdsignal-shortcode' );
						wp_localize_script(
							'crowdsignal-shortcode',
							'crowdsignal_shortcode_options',
							array(
								'script_url' => esc_url_raw(
									Assets::get_file_url_for_environment(
										'_inc/build/polldaddy-shortcode.min.js',
										'_inc/polldaddy-shortcode.js'
									)
								),
							)
						);

						/**
						 * Hook into the Crowdsignal shortcode before rendering.
						 *
						 * @since 8.4.0
						 *
						 * @param int $poll Poll ID.
						 */
						do_action( 'crowdsignal_shortcode_before', (int) $poll );

						return sprintf(
							'<a name="pd_a_%1$d"></a><div class="CSS_Poll PDS_Poll" id="PDI_container%1$d" data-settings="%2$s" style="%3$s%4$s"></div><div id="PD_superContainer"></div><noscript>%5$s</noscript>',
							absint( $poll ),
							esc_attr( wp_json_encode( $data ) ),
							$float,
							$margins,
							$poll_link
						);
					} else {
						if ( $inline ) {
							$attributes['cb'] = '';
						}

						wp_enqueue_script(
							'crowdsignal-' . absint( $poll ),
							esc_url( $poll_js . $attributes['cb'] ),
							array(),
							JETPACK__VERSION,
							true
						);

						/** This action is already documented in modules/shortcodes/crowdsignal.php */
						do_action( 'crowdsignal_shortcode_before', (int) $poll );

						return sprintf(
							'<a id="pd_a_%1$s"></a><div class="CSS_Poll PDS_Poll" id="PDI_container%1$s" style="%2$s%3$s"></div><div id="PD_superContainer"></div><noscript>%4$s</noscript>',
							absint( $poll ),
							$float,
							$margins,
							$poll_link
						);
					}
				}
			} elseif ( ! empty( $attributes['survey'] ) ) {
				/*
				 * Survey embed.
				 */

				if ( in_array(
					$attributes['type'],
					array( 'iframe', 'button', 'banner', 'slider' ),
					true
				) ) {

					if ( empty( $attributes['title'] ) ) {
						$attributes['title'] = esc_html__( 'Take Our Survey', 'jetpack' );
						if ( ! empty( $attributes['link_text'] ) ) {
							$attributes['title'] = $attributes['link_text'];
						}
					}

					if (
						'banner' === $attributes['type']
						|| 'slider' === $attributes['type']
					) {
						$inline = false;
					}

					$survey_url = '';

					if ( 'true' !== $attributes['survey'] ) {
						$survey = preg_replace( '/[^a-f0-9]/i', '', $attributes['survey'] );

						if ( 'crowdsignal.com' === $attributes['site'] ) {
							$survey_url = 'https://survey.fm/' . $survey;
						} else {
							$survey_url = 'https://polldaddy.com/s/' . $survey;
						}
					} elseif ( isset( $attributes['domain'] ) && isset( $attributes['id'] ) ) {
						$survey_url = 'https://' . $attributes['domain'] . '.survey.fm/' . $attributes['id'];
					}

					$survey_link = sprintf(
						'<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
						esc_url( $survey_url ),
						esc_html( $attributes['title'] )
					);

					$settings = array();

					if ( 'iframe' === $attributes['type'] ) {
						if ( 'auto' !== $attributes['height'] ) {
							if (
								is_numeric( $content_width )
								&& $content_width > 0
								&& is_numeric( $attributes['width'] )
								&& $attributes['width'] > $content_width
							) {
								$attributes['width'] = $content_width;
							}

							if ( ! $attributes['width'] ) {
								$attributes['width'] = '100%';
							} else {
								$attributes['width'] = (int) $attributes['width'];
							}

							if ( ! $attributes['height'] ) {
								$attributes['height'] = '600';
							} else {
								$attributes['height'] = (int) $attributes['height'];
							}

							return sprintf(
								'<iframe src="%1$s?iframe=1" frameborder="0" width="%2$d" height="%3$d" scrolling="auto" allowtransparency="true" marginheight="0" marginwidth="0">%4$s</iframe>',
								esc_url( $survey_url ),
								absint( $attributes['width'] ),
								absint( $attributes['height'] ),
								$survey_link
							);
						} elseif (
							! empty( $attributes['domain'] )
							&& ! empty( $attributes['id'] )
						) {
							$domain = preg_replace( '/[^a-z0-9\-]/i', '', $attributes['domain'] );
							$id     = preg_replace( '/[\/\?&\{\}]/', '', $attributes['id'] );

							$auto_src = esc_url( "https://{$domain}.survey.fm/{$id}" );
							$auto_src = wp_parse_url( $auto_src );

							if ( ! is_array( $auto_src ) || 0 === count( $auto_src ) ) {
								return '<!-- no crowdsignal output -->';
							}

							if ( ! isset( $auto_src['host'] ) || ! isset( $auto_src['path'] ) ) {
								return '<!-- no crowdsignal output -->';
							}

							$domain = $auto_src['host'] . '/';
							$id     = ltrim( $auto_src['path'], '/' );

							$settings = array(
								'type'   => $attributes['type'],
								'auto'   => true,
								'domain' => $domain,
								'id'     => $id,
								'site'   => $attributes['site'],
							);
						}
					} else {
						$text_color = preg_replace( '/[^a-f0-9]/i', '', $attributes['text_color'] );
						$back_color = preg_replace( '/[^a-f0-9]/i', '', $attributes['back_color'] );

						if (
							! in_array(
								$attributes['align'],
								array(
									'right',
									'left',
									'top-left',
									'top-right',
									'middle-left',
									'middle-right',
									'bottom-left',
									'bottom-right',
								),
								true
							)
						) {
							$attributes['align'] = '';
						}

						if (
							! in_array(
								$attributes['style'],
								array(
									'inline',
									'side',
									'corner',
									'rounded',
									'square',
								),
								true
							)
						) {
							$attributes['style'] = '';
						}

						$settings = array_filter(
							array(
								'title'      => wp_strip_all_tags( $attributes['title'] ),
								'type'       => $attributes['type'],
								'body'       => wp_strip_all_tags( $attributes['body'] ),
								'button'     => wp_strip_all_tags( $attributes['button'] ),
								'text_color' => $text_color,
								'back_color' => $back_color,
								'align'      => $attributes['align'],
								'style'      => $attributes['style'],
								'id'         => $survey,
								'site'       => $attributes['site'],
							)
						);
					}

					if ( empty( $settings ) ) {
						return '<!-- no crowdsignal output -->';
					}

					return $this->get_async_code( $settings, $survey_link, $survey_url );
				}
			} else {
				return '<!-- no crowdsignal output -->';
			}
		}

		/**
		 * Enqueue JavaScript containing all ratings / polls on the page.
		 * Hooked into wp_footer
		 */
		public function generate_scripts() {
			if ( is_array( self::$scripts ) ) {
				if ( isset( self::$scripts['rating'] ) ) {
					$script = "<!--//--><![CDATA[//><!--\n";
					foreach ( self::$scripts['rating'] as $rating ) {
						$script .= "PDRTJS_settings_{$rating['id']}{$rating['item_id']}={$rating['settings']}; if ( typeof PDRTJS_RATING !== 'undefined' ){if ( typeof PDRTJS_{$rating['id']}{$rating['item_id']} == 'undefined' ){PDRTJS_{$rating['id']}{$rating['item_id']} = new PDRTJS_RATING( PDRTJS_settings_{$rating['id']}{$rating['item_id']} );}}";
					}
					$script .= "\n//--><!]]>";

					wp_enqueue_script( 'crowdsignal-rating' );
					wp_add_inline_script(
						'crowdsignal-rating',
						$script,
						'before'
					);
				}

				if ( isset( self::$scripts['poll'] ) ) {
					foreach ( self::$scripts['poll'] as $poll_id => $poll ) {
						wp_enqueue_script(
							'crowdsignal-' . absint( $poll_id ),
							esc_url( $poll['url'] ),
							array(),
							JETPACK__VERSION,
							true
						);
					}
				}
			}
			self::$scripts = false;
		}

		/**
		 * Dynamically load the .js, if needed
		 *
		 * This hooks in late (priority 11) to infinite_scroll_render to determine
		 * a posteriori if a shortcode has been called.
		 */
		public function crowdsignal_shortcode_infinite() {
			// only try to load if a shortcode has been called and theme supports infinite scroll.
			if ( self::$add_script ) {
				wp_enqueue_script( 'crowdsignal-shortcode' );
				wp_localize_script(
					'crowdsignal-shortcode',
					'crowdsignal_shortcode_options',
					array(
						'script_url' => esc_url_raw(
							Assets::get_file_url_for_environment(
								'_inc/build/polldaddy-shortcode.min.js',
								'_inc/polldaddy-shortcode.js'
							)
						),
					)
				);
			}
		}
	}

	// Kick it all off.
	new CrowdsignalShortcode();

	if ( ! function_exists( 'crowdsignal_link' ) ) {
		/**
		 * Replace link with shortcode.
		 * Examples: https://poll.fm/10499328 | https://7iger.survey.fm/test-embed
		 *
		 * @param string $content Post content.
		 */
		function crowdsignal_link( $content ) {
			if (
				class_exists( 'Jetpack_AMP_Support' )
				&& Jetpack_AMP_Support::is_amp_request()
			) {
				return $content;
			}

			// Replace poll links.
			$content = jetpack_preg_replace_outside_tags(
				'!(?:\n|\A)https?://(polldaddy\.com/poll|poll\.fm)/([0-9]+?)(/.*)?(?:\n|\Z)!i',
				'[crowdsignal poll=$2]',
				$content
			);

			// Replace survey.fm links.
			$content = preg_replace(
				'!(?:\n|\A)https?://(.*).survey.fm/(.*)(/.*)?(?:\n|\Z)!i',
				'[crowdsignal type="iframe" survey="true" height="auto" domain="$1" id="$2"]',
				$content
			);

			return $content;
		}

		// higher priority because we need it before auto-link and autop get to it.
		add_filter( 'the_content', 'crowdsignal_link', 1 );
		add_filter( 'the_content_rss', 'crowdsignal_link', 1 );
	}
}
