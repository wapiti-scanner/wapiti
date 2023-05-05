<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * The Jetpack_RelatedPosts class.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Sync\Settings;

/**
 * The Jetpack_RelatedPosts class.
 */
class Jetpack_RelatedPosts {
	const VERSION   = '20211209';
	const SHORTCODE = 'jetpack-related-posts';

	/**
	 * Instance of the class.
	 *
	 * @var Jetpack_RelatedPosts
	 */
	private static $instance = null;

	/**
	 * Instance of the raw class (?).
	 *
	 * @var Jetpack_RelatedPosts
	 */
	private static $instance_raw = null;

	/**
	 * Creates and returns a static instance of Jetpack_RelatedPosts.
	 *
	 * @return Jetpack_RelatedPosts
	 */
	public static function init() {
		if ( ! self::$instance ) {
			if ( class_exists( 'WPCOM_RelatedPosts' ) && method_exists( 'WPCOM_RelatedPosts', 'init' ) ) {
				self::$instance = WPCOM_RelatedPosts::init();
			} else {
				self::$instance = new Jetpack_RelatedPosts();
			}
		}

		return self::$instance;
	}

	/**
	 * Creates and returns a static instance of Jetpack_RelatedPosts_Raw.
	 *
	 * @return Jetpack_RelatedPosts
	 */
	public static function init_raw() {
		if ( ! self::$instance_raw ) {
			if ( class_exists( 'WPCOM_RelatedPosts' ) && method_exists( 'WPCOM_RelatedPosts', 'init_raw' ) ) {
				self::$instance_raw = WPCOM_RelatedPosts::init_raw();
			} else {
				self::$instance_raw = new Jetpack_RelatedPosts_Raw();
			}
		}

		return self::$instance_raw;
	}

	/**
	 * Options.
	 *
	 * @var array $options
	 */
	protected $options;

	/**
	 * Allow feature toggle variable.
	 *
	 * @var bool
	 */
	protected $allow_feature_toggle;

	/**
	 * Blog character set.
	 *
	 * @var mixed
	 */
	protected $blog_charset;

	/**
	 * Convert character set.
	 *
	 * @var bool
	 */
	protected $convert_charset;

	/**
	 * Previous Post ID
	 *
	 * @var int
	 */
	protected $previous_post_id;

	/**
	 * Shortcode usage.
	 *
	 * @var bool
	 */
	protected $found_shortcode = false;

	/**
	 * Constructor for Jetpack_RelatedPosts.
	 *
	 * @uses get_option, add_action, apply_filters
	 */
	public function __construct() {
		$this->blog_charset    = get_option( 'blog_charset' );
		$this->convert_charset = ( function_exists( 'iconv' ) && ! preg_match( '/^utf\-?8$/i', $this->blog_charset ) );
		add_action( 'admin_init', array( $this, 'action_admin_init' ) );
		add_action( 'wp', array( $this, 'action_frontend_init' ) );

		if ( ! class_exists( 'Jetpack_Media_Summary' ) ) {
			require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media-summary.php';
		}

		// Add Related Posts to the REST API Post response.
		add_action( 'rest_api_init', array( $this, 'rest_register_related_posts' ) );

		Blocks::jetpack_register_block(
			'jetpack/related-posts',
			array(
				'render_callback' => array( $this, 'render_block' ),
				'supports'        => array(
					'color'      => array(
						'gradients' => true,
						'link'      => true,
					),
					'spacing'    => array(
						'margin'  => true,
						'padding' => true,
					),
					'typography' => array(
						'__experimentalFontFamily' => true,
						'fontSize'                 => true,
						'lineHeight'               => true,
					),
					'align'      => array( 'wide', 'full' ),
				),
			)
		);
	}

	/**
	 * Get the blog ID.
	 *
	 * @return Object current blog id.
	 */
	protected function get_blog_id() {
		return Jetpack_Options::get_option( 'id' );
	}

	/**
	 * =================
	 * ACTIONS & FILTERS
	 * =================
	 */

	/**
	 * Add a checkbox field to Settings > Reading for enabling related posts.
	 *
	 * @action admin_init
	 * @uses add_settings_field, __, register_setting, add_action
	 */
	public function action_admin_init() {

		// Add the setting field [jetpack_relatedposts] and place it in Settings > Reading.
		add_settings_field( 'jetpack_relatedposts', '<span id="jetpack_relatedposts">' . __( 'Related posts', 'jetpack' ) . '</span>', array( $this, 'print_setting_html' ), 'reading' );
		register_setting( 'reading', 'jetpack_relatedposts', array( $this, 'parse_options' ) );
		add_action( 'admin_head', array( $this, 'print_setting_head' ) );

		if ( 'options-reading.php' === $GLOBALS['pagenow'] ) {
			// Enqueue style for live preview on the reading settings page.
			$this->enqueue_assets( false, true );
		}
	}

	/**
	 * Load related posts assets if it's an eligible front end page or execute search and return JSON if it's an endpoint request.
	 *
	 * @global $_GET
	 * @action wp
	 * @uses add_shortcode, get_the_ID
	 */
	public function action_frontend_init() {
		// Add a shortcode handler that outputs nothing, this gets overridden later if we can display related content.
		add_shortcode( self::SHORTCODE, array( $this, 'get_client_rendered_html_unsupported' ) );

		if ( ! $this->enabled_for_request() ) {
			return;
		}

		if ( isset( $_GET['relatedposts'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading and checking if we need to generate a list of excuded posts, does not update anything on the site.
			$excludes = $this->parse_numeric_get_arg( 'relatedposts_exclude' );
			$this->action_frontend_init_ajax( $excludes );
		} else {
			if ( isset( $_GET['relatedposts_hit'], $_GET['relatedposts_origin'], $_GET['relatedposts_position'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- checking if fields are set to setup tracking, nothing is changing on the site.
				$this->previous_post_id = (int) $_GET['relatedposts_origin']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- fetching a previous post ID for tracking, nothing is changing on the site.
				$this->log_click( $this->previous_post_id, get_the_ID(), sanitize_text_field( wp_unslash( $_GET['relatedposts_position'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- logging the click for tracking, nothing is changing on the site.
			}

			$this->action_frontend_init_page();
		}
	}

	/**
	 * Render insertion point.
	 *
	 * @since 4.2.0
	 *
	 * @return string
	 */
	public function get_headline() {
		$options = $this->get_options();

		if ( $options['show_headline'] ) {
			$headline = sprintf(
				/** This filter is already documented in modules/sharedaddy/sharing-service.php */
				apply_filters( 'jetpack_sharing_headline_html', '<h3 class="jp-relatedposts-headline"><em>%s</em></h3>', esc_html( $options['headline'] ), 'related-posts' ),
				esc_html( $options['headline'] )
			);
		} else {
			$headline = '';
		}
		return $headline;
	}

	/**
	 * Adds a target to the post content to load related posts into if a shortcode for it did not already exist.
	 * Will skip adding the target if the post content contains a Related Posts block, if the 'get_the_excerpt'
	 * hook is in the current filter list, or if the site is running an FSE/Site Editor theme.
	 *
	 * @filter the_content
	 *
	 * @param string $content Post content.
	 *
	 * @returns string
	 */
	public function filter_add_target_to_dom( $content ) {
		if ( has_block( 'jetpack/related-posts' ) || Blocks::is_fse_theme() ) {
			return $content;
		}

		if ( ! $this->found_shortcode && ! doing_filter( 'get_the_excerpt' ) ) {
			if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
				$content .= "\n" . $this->get_server_rendered_html();
			} else {
				$content .= "\n" . $this->get_client_rendered_html();
			}
		}

		return $content;
	}

	/**
	 * Render static markup based on the Gutenberg block code
	 *
	 * @return string Rendered related posts HTML.
	 */
	public function get_server_rendered_html() {
		$rp_settings       = $this->get_options();
		$block_rp_settings = array(
			'displayThumbnails' => $rp_settings['show_thumbnails'],
			'showHeadline'      => $rp_settings['show_headline'],
			'displayDate'       => isset( $rp_settings['show_date'] ) ? (bool) $rp_settings['show_date'] : true,
			'displayContext'    => isset( $rp_settings['show_context'] ) && $rp_settings['show_context'],
			'postLayout'        => isset( $rp_settings['layout'] ) ? $rp_settings['layout'] : 'grid',
			'postsToShow'       => isset( $rp_settings['size'] ) ? $rp_settings['size'] : 3,
			/** This filter is already documented in modules/related-posts/jetpack-related-posts.php */
			'headline'          => apply_filters( 'jetpack_relatedposts_filter_headline', $this->get_headline() ),
			'isServerRendered'  => true,
		);

		return $this->render_block( $block_rp_settings );
	}

	/**
	 * Looks for our shortcode on the unfiltered content, this has to execute early.
	 *
	 * @filter the_content
	 * @param string $content - content of the post.
	 * @uses has_shortcode
	 * @return string $content
	 */
	public function test_for_shortcode( $content ) {
		$this->found_shortcode = has_shortcode( $content, self::SHORTCODE );

		return $content;
	}

	/**
	 * Returns the HTML for the related posts section.
	 *
	 * @uses esc_html__, apply_filters
	 * @return string
	 */
	public function get_client_rendered_html() {
		if ( Settings::is_syncing() ) {
			return '';
		}

		/**
		 * Filter the Related Posts headline.
		 *
		 * @module related-posts
		 *
		 * @since 3.0.0
		 *
		 * @param string $headline Related Posts heading.
		 */
		$headline = apply_filters( 'jetpack_relatedposts_filter_headline', $this->get_headline() );

		if ( $this->previous_post_id ) {
			$exclude = "data-exclude='{$this->previous_post_id}'";
		} else {
			$exclude = '';
		}

		return <<<EOT
<div id='jp-relatedposts' class='jp-relatedposts' $exclude>
	$headline
</div>
EOT;
	}

	/**
	 * Returns the HTML for the related posts section if it's running in the loop or other instances where we don't support related posts.
	 *
	 * @returns string
	 */
	public function get_client_rendered_html_unsupported() {
		if ( Settings::is_syncing() ) {
			return '';
		}
		return "\n\n<!-- Jetpack Related Posts is not supported in this context. -->\n\n";
	}

	/**
	 * ===============
	 * GUTENBERG BLOCK
	 * ===============
	 */

	/**
	 * Echoes out items for the Gutenberg block
	 *
	 * @param array $related_post The post oject.
	 * @param array $block_attributes The block attributes.
	 */
	public function render_block_item( $related_post, $block_attributes ) {
		$instance_id = 'related-posts-item-' . uniqid();
		$label_id    = $instance_id . '-label';

		$item_markup = sprintf(
			'<ul id="%1$s" aria-labelledby="%2$s" class="jp-related-posts-i2__post" role="menuitem">',
			esc_attr( $instance_id ),
			esc_attr( $label_id )
		);

		$item_markup .= sprintf(
			'<li class="jp-related-posts-i2__post-link"><a id="%1$s" href="%2$s" %4$s>%3$s</a></li>',
			esc_attr( $label_id ),
			esc_url( $related_post['url'] ),
			esc_attr( $related_post['title'] ),
			( ! empty( $related_post['rel'] ) ? 'rel="' . esc_attr( $related_post['rel'] ) . '"' : '' )
		);

		if ( ! empty( $block_attributes['show_thumbnails'] ) && ! empty( $related_post['img']['src'] ) ) {
			$img_link = sprintf(
				'<li class="jp-related-posts-i2__post-img-link"><a href="%1$s" %2$s><img src="%3$s" width="%4$s" height="%5$s" alt="%6$s" loading="lazy" /></a></li>',
				esc_url( $related_post['url'] ),
				( ! empty( $related_post['rel'] ) ? 'rel="' . esc_attr( $related_post['rel'] ) . '"' : '' ),
				esc_url( $related_post['img']['src'] ),
				esc_attr( $related_post['img']['width'] ),
				esc_attr( $related_post['img']['height'] ),
				esc_attr( $related_post['img']['alt_text'] )
			);

			$item_markup .= $img_link;
		}

		if ( $block_attributes['show_date'] ) {
			$date_tag = sprintf(
				'<li class="jp-related-posts-i2__post-date">%1$s</li>',
				esc_html( $related_post['date'] )
			);

			$item_markup .= $date_tag;
		}

		if ( ( $block_attributes['show_context'] ) && ! empty( $related_post['context'] ) ) {
			$context_tag = sprintf(
				'<li class="jp-related-posts-i2__post-context">%1$s</li>',
				esc_html( $related_post['context'] )
			);

			$item_markup .= $context_tag;
		}

		$item_markup .= '</ul>';

		return $item_markup;
	}

	/**
	 * Render a related posts row.
	 *
	 * @param array $posts The posts to render into the row.
	 * @param array $block_attributes Block attributes.
	 */
	public function render_block_row( $posts, $block_attributes ) {
		$rows_markup = '';
		foreach ( $posts as $post ) {
			$rows_markup .= $this->render_block_item( $post, $block_attributes );
		}
		return sprintf(
			'<div class="jp-related-posts-i2__row" data-post-count="%1$s">%2$s</div>',
			count( $posts ),
			$rows_markup
		);
	}

	/**
	 * Render the related posts markup.
	 *
	 * @param array $attributes Block attributes.
	 * @return string
	 */
	public function render_block( $attributes ) {
		$post_id          = get_the_ID();
		$block_attributes = array(
			'headline'        => isset( $attributes['headline'] ) ? $attributes['headline'] : null,
			'show_thumbnails' => isset( $attributes['displayThumbnails'] ) && $attributes['displayThumbnails'],
			'show_date'       => isset( $attributes['displayDate'] ) ? (bool) $attributes['displayDate'] : true,
			'show_context'    => isset( $attributes['displayContext'] ) && $attributes['displayContext'],
			'layout'          => isset( $attributes['postLayout'] ) && 'list' === $attributes['postLayout'] ? $attributes['postLayout'] : 'grid',
			'size'            => ! empty( $attributes['postsToShow'] ) ? absint( $attributes['postsToShow'] ) : 3,
		);

		$excludes = $this->parse_numeric_get_arg( 'relatedposts_origin' );

		$related_posts = $this->get_for_post_id(
			$post_id,
			array(
				'size'             => $block_attributes['size'],
				'exclude_post_ids' => $excludes,
			)
		);

		$display_lower_row = $block_attributes['size'] > 3;

		if ( empty( $related_posts ) ) {
			return '';
		}

		switch ( count( $related_posts ) ) {
			case 2:
			case 4:
			case 5:
				$top_row_end = 2;
				break;

			default:
				$top_row_end = 3;
				break;
		}

		$upper_row_posts = array_slice( $related_posts, 0, $top_row_end );
		$lower_row_posts = array_slice( $related_posts, $top_row_end );

		$rows_markup = $this->render_block_row( $upper_row_posts, $block_attributes );
		if ( $display_lower_row ) {
			$rows_markup .= $this->render_block_row( $lower_row_posts, $block_attributes );
		}

		if ( empty( $attributes['isServerRendered'] ) ) {
			// The get_server_rendered_html() path won't register a block,
			// so only apply block supports when not server rendered.
			$wrapper_attributes = \WP_Block_Supports::get_instance()->apply_block_supports();
		}

		$display_markup = sprintf(
			'<nav class="jp-relatedposts-i2%1$s"%2$s data-layout="%3$s">%4$s%5$s</nav>',
			! empty( $wrapper_attributes['class'] ) ? ' ' . esc_attr( $wrapper_attributes['class'] ) : '',
			! empty( $wrapper_attributes['style'] ) ? ' style="' . esc_attr( $wrapper_attributes['style'] ) . '"' : '',
			esc_attr( $block_attributes['layout'] ),
			$block_attributes['headline'],
			$rows_markup
		);

		/**
		 * Filter the output HTML of Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 10.7
		 *
		 * @param string $display_markup HTML output of Related Posts.
		 * @param int|false get_the_ID() Post ID of the post for which we are retrieving Related Posts.
		 * @param array $related_posts Array of related posts.
		 * @param array $block_attributes Array of Block attributes.
		 */
		return (string) apply_filters( 'jetpack_related_posts_display_markup', $display_markup, $post_id, $related_posts, $block_attributes );
	}

	/**
	 * ========================
	 * PUBLIC UTILITY FUNCTIONS
	 * ========================
	 */

	/**
	 * Parse a numeric GET variable to an array of values.
	 *
	 * @since 6.9.0
	 *
	 * @uses absint
	 *
	 * @param string $arg Name of the GET variable.
	 * @return array $result Parsed value(s)
	 */
	public function parse_numeric_get_arg( $arg ) {
		$result = array();

		if ( isset( $_GET[ $arg ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- requests are used to generate a list of related posts we want to exclude.
			if ( is_string( $_GET[ $arg ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$result = explode( ',', sanitize_text_field( wp_unslash( $_GET[ $arg ] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			} elseif ( is_array( $_GET[ $arg ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$args   = array_map( 'sanitize_text_field', wp_unslash( $_GET[ $arg ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$result = array_values( $args );
			}

			$result = array_unique( array_filter( array_map( 'absint', $result ) ) );
		}

		return $result;
	}

	/**
	 * Gets options set for Jetpack_RelatedPosts and merge with defaults.
	 *
	 * @uses Jetpack_Options::get_option, apply_filters
	 * @return array
	 */
	public function get_options() {
		if ( null === $this->options ) {
			$this->options = Jetpack_Options::get_option( 'relatedposts', array() );
			if ( ! is_array( $this->options ) ) {
				$this->options = array();
			}
			if ( ! isset( $this->options['enabled'] ) ) {
				$this->options['enabled'] = true;
			}
			if ( ! isset( $this->options['show_headline'] ) ) {
				$this->options['show_headline'] = true;
			}
			if ( ! isset( $this->options['show_thumbnails'] ) ) {
				$this->options['show_thumbnails'] = false;
			}
			if ( ! isset( $this->options['show_date'] ) ) {
				$this->options['show_date'] = true;
			}
			if ( ! isset( $this->options['show_context'] ) ) {
				$this->options['show_context'] = true;
			}
			if ( ! isset( $this->options['layout'] ) ) {
				$this->options['layout'] = 'grid';
			}
			if ( ! isset( $this->options['headline'] ) ) {
				$this->options['headline'] = esc_html__( 'Related', 'jetpack' );
			}
			if ( empty( $this->options['size'] ) || (int) $this->options['size'] < 1 ) {
				$this->options['size'] = 3;
			}

			/**
			 * Filter Related Posts basic options.
			 *
			 * @module related-posts
			 *
			 * @since 2.8.0
			 *
			 * @param array $this->_options Array of basic Related Posts options.
			 */
			$this->options = apply_filters( 'jetpack_relatedposts_filter_options', $this->options );
		}

		return $this->options;
	}

	/**
	 * Gets options.
	 *
	 * @param string $option_name - option we want to get.
	 */
	public function get_option( $option_name ) {
		$options = $this->get_options();

		if ( isset( $options[ $option_name ] ) ) {
			return $options[ $option_name ];
		}

		return false;
	}

	/**
	 * Parses input and returns normalized options array.
	 *
	 * @param array $input - input we're parsing.
	 * @uses self::get_options
	 * @return array
	 */
	public function parse_options( $input ) {
		$current = $this->get_options();

		if ( ! is_array( $input ) ) {
			$input = array();
		}

		if (
			! isset( $input['enabled'] )
			|| isset( $input['show_date'] )
			|| isset( $input['show_context'] )
			|| isset( $input['layout'] )
			|| isset( $input['headline'] )
			) {
			$input['enabled'] = '1';
		}

		if ( '1' == $input['enabled'] ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- expecting string, but may return bools.
			$current['enabled']         = true;
			$current['show_headline']   = ( isset( $input['show_headline'] ) && '1' == $input['show_headline'] ); // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
			$current['show_thumbnails'] = ( isset( $input['show_thumbnails'] ) && '1' == $input['show_thumbnails'] ); // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
			$current['show_date']       = ( isset( $input['show_date'] ) && '1' == $input['show_date'] ); // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
			$current['show_context']    = ( isset( $input['show_context'] ) && '1' == $input['show_context'] ); // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
			$current['layout']          = isset( $input['layout'] ) && in_array( $input['layout'], array( 'grid', 'list' ), true ) ? $input['layout'] : 'grid';
			$current['headline']        = isset( $input['headline'] ) ? $input['headline'] : esc_html__( 'Related', 'jetpack' );
		} else {
			$current['enabled'] = false;
		}

		if ( isset( $input['size'] ) && (int) $input['size'] > 0 ) {
			$current['size'] = (int) $input['size'];
		} else {
			$current['size'] = null;
		}
		return $current;
	}

	/**
	 * HTML for admin settings page.
	 *
	 * @uses self::get_options, checked, esc_html__
	 * @returns null
	 */
	public function print_setting_html() {
		$options = $this->get_options();

		$ui_settings_template = <<<EOT
<p class="description">%s</p>
<ul id="settings-reading-relatedposts-customize">
	<li>
		<label><input name="jetpack_relatedposts[show_headline]" type="checkbox" value="1" %s /> %s</label>
	</li>
	<li>
		<label><input name="jetpack_relatedposts[show_thumbnails]" type="checkbox" value="1" %s /> %s</label>
	</li>
	<li>
		<label><input name="jetpack_relatedposts[show_date]" type="checkbox" value="1" %s /> %s</label>
	</li>
	<li>
		<label><input name="jetpack_relatedposts[show_context]" type="checkbox" value="1" %s /> %s</label>
	</li>
</ul>
<div id='settings-reading-relatedposts-preview'>
	%s
	<div id="jp-relatedposts" class="jp-relatedposts"></div>
</div>
EOT;
		$ui_settings          = sprintf(
			$ui_settings_template,
			esc_html__( 'The following settings will impact all related posts on your site, except for those you created via the block editor:', 'jetpack' ),
			checked( $options['show_headline'], true, false ),
			esc_html__( 'Highlight related content with a heading', 'jetpack' ),
			checked( $options['show_thumbnails'], true, false ),
			esc_html__( 'Show a thumbnail image where available', 'jetpack' ),
			checked( $options['show_date'], true, false ),
			esc_html__( 'Show entry date', 'jetpack' ),
			checked( $options['show_context'], true, false ),
			esc_html__( 'Show context (category or tag)', 'jetpack' ),
			esc_html__( 'Preview:', 'jetpack' )
		);

		if ( ! $this->allow_feature_toggle() ) {
			$template = <<<EOT
<input type="hidden" name="jetpack_relatedposts[enabled]" value="1" />
%s
EOT;
			printf(
				$template, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				$ui_settings // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- data is escaped when variable is set.
			);
		} else {
			$template = <<<EOT
<ul id="settings-reading-relatedposts">
	<li>
		<label><input type="radio" name="jetpack_relatedposts[enabled]" value="0" class="tog" %s /> %s</label>
	</li>
	<li>
		<label><input type="radio" name="jetpack_relatedposts[enabled]" value="1" class="tog" %s /> %s</label>
		%s
	</li>
</ul>
EOT;
			printf(
				$template, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				checked( $options['enabled'], false, false ),
				esc_html__( 'Hide related content after posts', 'jetpack' ),
				checked( $options['enabled'], true, false ),
				esc_html__( 'Show related content after posts', 'jetpack' ),
				$ui_settings // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- data is escaped when variable is set.
			);
		}
	}

	/**
	 * Head JS/CSS for admin settings page.
	 *
	 * @uses esc_html__
	 * @returns null
	 */
	public function print_setting_head() {

		// only dislay the Related Posts JavaScript on the Reading Settings Admin Page.
		$current_screen = get_current_screen();

		if ( $current_screen === null ) {
			return;
		}

		if ( 'options-reading' !== $current_screen->id ) {
			return;
		}

		$related_headline = sprintf(
			'<h3 class="jp-relatedposts-headline"><em>%s</em></h3>',
			esc_html__( 'Related', 'jetpack' )
		);

		$href_params            = 'class="jp-relatedposts-post-a" href="#jetpack_relatedposts" rel="nofollow" data-origin="0" data-position="0"';
		$related_with_images    = <<<EOT
<div class="jp-relatedposts-items jp-relatedposts-items-visual">
	<div class="jp-relatedposts-post jp-relatedposts-post0 jp-relatedposts-post-thumbs" data-post-id="0" data-post-format="image">
		<a $href_params>
			<img class="jp-relatedposts-post-img" src="https://jetpackme.files.wordpress.com/2019/03/cat-blog.png" width="350" alt="Big iPhone/iPad Update Now Available" scale="0">
		</a>
		<h4 class="jp-relatedposts-post-title">
			<a $href_params>Big iPhone/iPad Update Now Available</a>
		</h4>
		<p class="jp-relatedposts-post-excerpt">Big iPhone/iPad Update Now Available</p>
		<p class="jp-relatedposts-post-context">In "Mobile"</p>
	</div>
	<div class="jp-relatedposts-post jp-relatedposts-post1 jp-relatedposts-post-thumbs" data-post-id="0" data-post-format="image">
		<a $href_params>
			<img class="jp-relatedposts-post-img" src="https://jetpackme.files.wordpress.com/2019/03/devices.jpg" width="350" alt="The WordPress for Android App Gets a Big Facelift" scale="0">
		</a>
		<h4 class="jp-relatedposts-post-title">
			<a $href_params>The WordPress for Android App Gets a Big Facelift</a>
		</h4>
		<p class="jp-relatedposts-post-excerpt">The WordPress for Android App Gets a Big Facelift</p>
		<p class="jp-relatedposts-post-context">In "Mobile"</p>
	</div>
	<div class="jp-relatedposts-post jp-relatedposts-post2 jp-relatedposts-post-thumbs" data-post-id="0" data-post-format="image">
		<a $href_params>
			<img class="jp-relatedposts-post-img" src="https://jetpackme.files.wordpress.com/2019/03/mobile-wedding.jpg" width="350" alt="Upgrade Focus: VideoPress For Weddings" scale="0">
		</a>
		<h4 class="jp-relatedposts-post-title">
			<a $href_params>Upgrade Focus: VideoPress For Weddings</a>
		</h4>
		<p class="jp-relatedposts-post-excerpt">Upgrade Focus: VideoPress For Weddings</p>
		<p class="jp-relatedposts-post-context">In "Upgrade"</p>
	</div>
</div>
EOT;
		$related_with_images    = str_replace( "\n", '', $related_with_images );
		$related_without_images = <<<EOT
<div class="jp-relatedposts-items jp-relatedposts-items-minimal">
	<p class="jp-relatedposts-post jp-relatedposts-post0" data-post-id="0" data-post-format="image">
		<span class="jp-relatedposts-post-title"><a $href_params>Big iPhone/iPad Update Now Available</a></span>
		<span class="jp-relatedposts-post-context">In "Mobile"</span>
	</p>
	<p class="jp-relatedposts-post jp-relatedposts-post1" data-post-id="0" data-post-format="image">
		<span class="jp-relatedposts-post-title"><a $href_params>The WordPress for Android App Gets a Big Facelift</a></span>
		<span class="jp-relatedposts-post-context">In "Mobile"</span>
	</p>
	<p class="jp-relatedposts-post jp-relatedposts-post2" data-post-id="0" data-post-format="image">
		<span class="jp-relatedposts-post-title"><a $href_params>Upgrade Focus: VideoPress For Weddings</a></span>
		<span class="jp-relatedposts-post-context">In "Upgrade"</span>
	</p>
</div>
EOT;
		$related_without_images = str_replace( "\n", '', $related_without_images );

		if ( $this->allow_feature_toggle() ) {
			$extra_css = '#settings-reading-relatedposts-customize { padding-left:2em; margin-top:.5em; }';
		} else {
			$extra_css = '';
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo <<<EOT
<style type="text/css">
	#settings-reading-relatedposts .disabled { opacity:.5; filter:Alpha(opacity=50); }
	#settings-reading-relatedposts-preview .jp-relatedposts { background:#fff; padding:.5em; width:75%; }
	$extra_css
</style>
<script type="text/javascript">
	jQuery( document ).ready( function($) {
		var update_ui = function() {
			var is_enabled = true;
			if ( 'radio' == $( 'input[name="jetpack_relatedposts[enabled]"]' ).attr('type') ) {
				if ( '0' == $( 'input[name="jetpack_relatedposts[enabled]"]:checked' ).val() ) {
					is_enabled = false;
				}
			}
			if ( is_enabled ) {
				$( '#settings-reading-relatedposts-customize' )
					.removeClass( 'disabled' )
					.find( 'input' )
					.attr( 'disabled', false );
				$( '#settings-reading-relatedposts-preview' )
					.removeClass( 'disabled' );
			} else {
				$( '#settings-reading-relatedposts-customize' )
					.addClass( 'disabled' )
					.find( 'input' )
					.attr( 'disabled', true );
				$( '#settings-reading-relatedposts-preview' )
					.addClass( 'disabled' );
			}
		};

		var update_preview = function() {
			var html = '';
			if ( $( 'input[name="jetpack_relatedposts[show_headline]"]:checked' ).length ) {
				html += '$related_headline';
			}
			if ( $( 'input[name="jetpack_relatedposts[show_thumbnails]"]:checked' ).length ) {
				html += '$related_with_images';
			} else {
				html += '$related_without_images';
			}
			$( '#settings-reading-relatedposts-preview .jp-relatedposts' ).html( html );
			if ( $( 'input[name="jetpack_relatedposts[show_date]"]:checked' ).length ) {
				$( '.jp-relatedposts-post-title' ).each( function() {
					$( this ).after( $( '<span>August 8, 2005</span>' ) );
				} );
			}
			if ( $( 'input[name="jetpack_relatedposts[show_context]"]:checked' ).length ) {
				$( '.jp-relatedposts-post-context' ).show();
			} else {
				$( '.jp-relatedposts-post-context' ).hide();
			}
			$( '#settings-reading-relatedposts-preview .jp-relatedposts' ).show();
		};

		// Update on load
		update_preview();
		update_ui();

		// Update on change
		$( '#settings-reading-relatedposts-customize input' )
			.change( update_preview );
		$( '#settings-reading-relatedposts' )
			.find( 'input.tog' )
			.change( update_ui );
	});
</script>
EOT;
	}

	/**
	 * Gets an array of related posts that match the given post_id.
	 *
	 * @param int   $post_id Post which we want to find related posts for.
	 * @param array $args - params to use when building Elasticsearch filters to narrow down the search domain.
	 * @uses self::get_options, get_post_type, wp_parse_args, apply_filters
	 * @return array
	 */
	public function get_for_post_id( $post_id, array $args ) {
		$options = $this->get_options();

		if ( ! empty( $args['size'] ) ) {
			$options['size'] = $args['size'];
		}

		if (
			! $options['enabled']
			|| 0 === (int) $post_id
			|| empty( $options['size'] )
		) {
			return array();
		}

		$defaults = array(
			'size'             => (int) $options['size'],
			'post_type'        => get_post_type( $post_id ),
			'post_formats'     => array(),
			'has_terms'        => array(),
			'date_range'       => array(),
			'exclude_post_ids' => array(),
		);
		$args     = wp_parse_args( $args, $defaults );
		/**
		 * Filter the arguments used to retrieve a list of Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array $args Array of options to retrieve Related Posts.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$args = apply_filters( 'jetpack_relatedposts_filter_args', $args, $post_id );

		$filters = $this->get_es_filters_from_args( $post_id, $args );
		/**
		 * Filter Elasticsearch options used to calculate Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array $filters Array of Elasticsearch filters based on the post_id and args.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$filters = apply_filters( 'jetpack_relatedposts_filter_filters', $filters, $post_id );

		$results = $this->get_related_posts( $post_id, $args['size'], $filters );
		/**
		 * Filter the array of related posts matched by Elasticsearch.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array $results Array of related posts matched by Elasticsearch.
		 * @param int $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		return apply_filters( 'jetpack_relatedposts_returned_results', $results, $post_id );
	}

	/**
	 * =========================
	 * PRIVATE UTILITY FUNCTIONS
	 * =========================
	 */

	/**
	 * Creates an array of Elasticsearch filters based on the post_id and args.
	 *
	 * @param int   $post_id - the post ID.
	 * @param array $args - the arguments.
	 * @uses apply_filters, get_post_types, get_post_format_strings
	 * @return array
	 */
	protected function get_es_filters_from_args( $post_id, array $args ) {
		$filters = array();

		/**
		 * Filter the terms used to search for Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array $args['has_terms'] Array of terms associated to the Related Posts.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$args['has_terms'] = apply_filters( 'jetpack_relatedposts_filter_has_terms', $args['has_terms'], $post_id );
		if ( ! empty( $args['has_terms'] ) ) {
			foreach ( (array) $args['has_terms'] as $term ) {
				if ( mb_strlen( $term->taxonomy ) ) {
					switch ( $term->taxonomy ) {
						case 'post_tag':
							$tax_fld = 'tag.slug';
							break;
						case 'category':
							$tax_fld = 'category.slug';
							break;
						default:
							$tax_fld = 'taxonomy.' . $term->taxonomy . '.slug';
							break;
					}
					$filters[] = array( 'term' => array( $tax_fld => $term->slug ) );
				}
			}
		}

		/**
		 * Filter the Post Types where we search Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array $args['post_type'] Array of Post Types.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$args['post_type'] = apply_filters( 'jetpack_relatedposts_filter_post_type', $args['post_type'], $post_id );
		$valid_post_types  = get_post_types();
		if ( is_array( $args['post_type'] ) ) {
			$sanitized_post_types = array();
			foreach ( $args['post_type'] as $pt ) {
				if ( in_array( $pt, $valid_post_types, true ) ) {
					$sanitized_post_types[] = $pt;
				}
			}
			if ( ! empty( $sanitized_post_types ) ) {
				$filters[] = array( 'terms' => array( 'post_type' => $sanitized_post_types ) );
			}
		} elseif ( in_array( $args['post_type'], $valid_post_types, true ) && 'all' !== $args['post_type'] ) {
				$filters[] = array( 'term' => array( 'post_type' => $args['post_type'] ) );
		}

		/**
		 * Filter the Post Formats where we search Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 3.3.0
		 *
		 * @param array $args['post_formats'] Array of Post Formats.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$args['post_formats']   = apply_filters( 'jetpack_relatedposts_filter_post_formats', $args['post_formats'], $post_id );
		$valid_post_formats     = get_post_format_strings();
		$sanitized_post_formats = array();
		foreach ( $args['post_formats'] as $pf ) {
			if ( array_key_exists( $pf, $valid_post_formats ) ) {
				$sanitized_post_formats[] = $pf;
			}
		}
		if ( ! empty( $sanitized_post_formats ) ) {
			$filters[] = array( 'terms' => array( 'post_format' => $sanitized_post_formats ) );
		}

		/**
		 * Filter the date range used to search Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array $args['date_range'] Array of a month interval where we search Related Posts.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$args['date_range'] = apply_filters( 'jetpack_relatedposts_filter_date_range', $args['date_range'], $post_id );
		if ( is_array( $args['date_range'] ) && ! empty( $args['date_range'] ) ) {
			$args['date_range'] = array_map( 'intval', $args['date_range'] );
			if ( ! empty( $args['date_range']['from'] ) && ! empty( $args['date_range']['to'] ) ) {
				$filters[] = array(
					'range' => array(
						'date_gmt' => $this->get_coalesced_range( $args['date_range'] ),
					),
				);
			}
		}

		/**
		 * Filter the Post IDs excluded from appearing in Related Posts.
		 *
		 * @module related-posts
		 *
		 * @since 2.9.0
		 *
		 * @param array $args['exclude_post_ids'] Array of Post IDs.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$args['exclude_post_ids'] = apply_filters( 'jetpack_relatedposts_filter_exclude_post_ids', $args['exclude_post_ids'], $post_id );
		if ( ! empty( $args['exclude_post_ids'] ) && is_array( $args['exclude_post_ids'] ) ) {
			$excluded_post_ids = array();
			foreach ( $args['exclude_post_ids'] as $exclude_post_id ) {
				$exclude_post_id = (int) $exclude_post_id;
				if ( $exclude_post_id > 0 ) {
					$excluded_post_ids[] = $exclude_post_id;
				}
			}
			$filters[] = array( 'not' => array( 'terms' => array( 'post_id' => $excluded_post_ids ) ) );
		}

		return $filters;
	}

	/**
	 * Takes a range and coalesces it into a month interval bracketed by a time as determined by the blog_id to enhance caching.
	 *
	 * @todo Rewrite this function with proper date handling rather than `strtotime()` and `date()`.
	 *
	 * @param array $date_range - the date range.
	 * @return array
	 */
	protected function get_coalesced_range( array $date_range ) {
		$now           = time();
		$coalesce_time = $this->get_blog_id() % 86400;
		$current_time  = $now - strtotime( 'today', $now );

		if ( $current_time < $coalesce_time && '01' === date( 'd', $now ) ) { // phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
			// Move back 1 period.
			return array(
				'from' => date( 'Y-m-01', strtotime( '-1 month', $date_range['from'] ) ) . ' ' . date( 'H:i:s', $coalesce_time ), //phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
				'to'   => date( 'Y-m-01', $date_range['to'] ) . ' ' . date( 'H:i:s', $coalesce_time ), //phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
			);
		} else {
			// Use current period.
			return array(
				'from' => date( 'Y-m-01', $date_range['from'] ) . ' ' . date( 'H:i:s', $coalesce_time ), //phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
				'to'   => date( 'Y-m-01', strtotime( '+1 month', $date_range['to'] ) ) . ' ' . date( 'H:i:s', $coalesce_time ), //phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
			);
		}
	}

	/**
	 * Generate and output ajax response for related posts API call.
	 * NOTE: Calls exit() to end all further processing after payload has been outputed.
	 *
	 * @param array $excludes array of post_ids to exclude.
	 * @uses send_nosniff_header, self::get_for_post_id, get_the_ID
	 */
	protected function action_frontend_init_ajax( array $excludes ) {
		define( 'DOING_AJAX', true );

		header( 'Content-type: application/json; charset=utf-8' ); // JSON can only be UTF-8.
		send_nosniff_header();

		$options = $this->get_options();

		if ( isset( $_GET['jetpackrpcustomize'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- adds dummy content if we're in the customizer.

			// If we're in the customizer, add dummy content.
			$date_now      = current_time( get_option( 'date_format' ) );
			$related_posts = array(
				array(
					'id'       => - 1,
					'url'      => 'https://jetpackme.files.wordpress.com/2019/03/cat-blog.png',
					'url_meta' => array(
						'origin'   => 0,
						'position' => 0,
					),
					'title'    => esc_html__( 'Big iPhone/iPad Update Now Available', 'jetpack' ),
					'date'     => $date_now,
					'format'   => false,
					'excerpt'  => esc_html__( 'It is that time of the year when devices are shiny again.', 'jetpack' ),
					'rel'      => 'nofollow',
					'context'  => esc_html__( 'In "Mobile"', 'jetpack' ),
					'img'      => array(
						'src'    => 'https://jetpackme.files.wordpress.com/2019/03/cat-blog.png',
						'width'  => 350,
						'height' => 200,
					),
					'classes'  => array(),
				),
				array(
					'id'       => - 1,
					'url'      => 'https://jetpackme.files.wordpress.com/2019/03/devices.jpg',
					'url_meta' => array(
						'origin'   => 0,
						'position' => 0,
					),
					'title'    => esc_html__( 'The WordPress for Android App Gets a Big Facelift', 'jetpack' ),
					'date'     => $date_now,
					'format'   => false,
					'excerpt'  => esc_html__( 'Writing is new again in Android with the new WordPress app.', 'jetpack' ),
					'rel'      => 'nofollow',
					'context'  => esc_html__( 'In "Mobile"', 'jetpack' ),
					'img'      => array(
						'src'    => 'https://jetpackme.files.wordpress.com/2019/03/devices.jpg',
						'width'  => 350,
						'height' => 200,
					),
					'classes'  => array(),
				),
				array(
					'id'       => - 1,
					'url'      => 'https://jetpackme.files.wordpress.com/2019/03/mobile-wedding.jpg',
					'url_meta' => array(
						'origin'   => 0,
						'position' => 0,
					),
					'title'    => esc_html__( 'Upgrade Focus, VideoPress for weddings', 'jetpack' ),
					'date'     => $date_now,
					'format'   => false,
					'excerpt'  => esc_html__( 'Weddings are in the spotlight now with VideoPress for weddings.', 'jetpack' ),
					'rel'      => 'nofollow',
					'context'  => esc_html__( 'In "Mobile"', 'jetpack' ),
					'img'      => array(
						'src'    => 'https://jetpackme.files.wordpress.com/2019/03/mobile-wedding.jpg',
						'width'  => 350,
						'height' => 200,
					),
					'classes'  => array(),
				),
			);

			for ( $total = 0; $total < $options['size'] - 3; $total++ ) {
				$related_posts[] = $related_posts[ $total ];
			}

			$current_post = get_post();

			// Exclude current post after filtering to make sure it's excluded and not lost during filtering.
			$excluded_posts = array_merge(
				/** This filter is already documented in modules/related-posts/jetpack-related-posts.php */
				apply_filters( 'jetpack_relatedposts_filter_exclude_post_ids', array() ),
				array( $current_post->ID )
			);

			// Fetch posts with featured image.
			$with_post_thumbnails = get_posts(
				array(
					'posts_per_page'   => $options['size'],
					'post__not_in'     => $excluded_posts,
					'post_type'        => $current_post->post_type,
					'meta_key'         => '_thumbnail_id',
					'suppress_filters' => false,
				)
			);

			// If we don't have enough, fetch posts without featured image.
			$more = $options['size'] - count( $with_post_thumbnails );
			if ( 0 < $more ) {
				$no_post_thumbnails = get_posts(
					array(
						'posts_per_page'   => $more,
						'post__not_in'     => $excluded_posts,
						'post_type'        => $current_post->post_type,
						'meta_query'       => array(
							array(
								'key'     => '_thumbnail_id',
								'compare' => 'NOT EXISTS',
							),
						),
						'suppress_filters' => false,
					)
				);
			} else {
				$no_post_thumbnails = array();
			}

			foreach ( array_merge( $with_post_thumbnails, $no_post_thumbnails ) as $index => $real_post ) {
				$related_posts[ $index ]['id']      = $real_post->ID;
				$related_posts[ $index ]['url']     = esc_url( get_permalink( $real_post ) );
				$related_posts[ $index ]['title']   = $this->to_utf8( $this->get_title( $real_post->post_title, $real_post->post_content, $real_post->ID ) );
				$related_posts[ $index ]['date']    = get_the_date( '', $real_post );
				$related_posts[ $index ]['excerpt'] = html_entity_decode( $this->to_utf8( $this->get_excerpt( $real_post->post_excerpt, $real_post->post_content ) ), ENT_QUOTES, 'UTF-8' );
				$related_posts[ $index ]['img']     = $this->generate_related_post_image_params( $real_post->ID );
				$related_posts[ $index ]['context'] = $this->generate_related_post_context( $real_post->ID );
			}
		} else {
			$related_posts = $this->get_for_post_id(
				get_the_ID(),
				array(
					'exclude_post_ids' => $excludes,
				)
			);
		}

		$response = array(
			'version'         => self::VERSION,
			'show_thumbnails' => (bool) $options['show_thumbnails'],
			'show_date'       => (bool) $options['show_date'],
			'show_context'    => (bool) $options['show_context'],
			'layout'          => (string) $options['layout'],
			'headline'        => (string) $options['headline'],
			'items'           => array(),
		);

		if ( count( $related_posts ) === $options['size'] ) {
			$response['items'] = $related_posts;
		}

		echo wp_json_encode( $response );

		exit();
	}

	/**
	 * Returns a UTF-8 encoded array of post information for the given post_id
	 *
	 * @param int $post_id - the post ID.
	 * @param int $position - position of the post.
	 * @param int $origin - The post id that this is related to.
	 * @uses get_post, get_permalink, remove_query_arg, get_post_format, apply_filters
	 * @return array
	 */
	public function get_related_post_data_for_post( $post_id, $position, $origin ) {
		$post = get_post( $post_id );
		return array(
			'id'       => $post->ID,
			'url'      => get_permalink( $post->ID ),
			'url_meta' => array(
				'origin'   => $origin,
				'position' => $position,
			),
			'title'    => $this->to_utf8( $this->get_title( $post->post_title, $post->post_content, $post->ID ) ),
			'date'     => get_the_date( '', $post->ID ),
			'format'   => get_post_format( $post->ID ),
			'excerpt'  => html_entity_decode( $this->to_utf8( $this->get_excerpt( $post->post_excerpt, $post->post_content ) ), ENT_QUOTES, 'UTF-8' ),
			/**
			 * Filters the rel attribute for the Related Posts' links.
			 *
			 * @module related-posts
			 *
			 * @since 3.7.0
			 * @since 7.9.0 - Change Default value to empty.
			 *
			 * @param string $link_rel Link rel attribute for Related Posts' link. Default is empty.
			 * @param int    $post->ID Post ID.
			 */
			'rel'      => apply_filters( 'jetpack_relatedposts_filter_post_link_rel', '', $post->ID ),
			/**
			 * Filter the context displayed below each Related Post.
			 *
			 * @module related-posts
			 *
			 * @since 3.0.0
			 *
			 * @param string $this->to_utf8( $this->generate_related_post_context( $post->ID ) ) Context displayed below each related post.
			 * @param int $post_id Post ID of the post for which we are retrieving Related Posts.
			 */
			'context'  => apply_filters(
				'jetpack_relatedposts_filter_post_context',
				$this->to_utf8( $this->generate_related_post_context( $post->ID ) ),
				$post->ID
			),
			'img'      => $this->generate_related_post_image_params( $post->ID ),
			/**
			 * Filter the post css classes added on HTML markup.
			 *
			 * @module related-posts
			 *
			 * @since 3.8.0
			 *
			 * @param array array() CSS classes added on post HTML markup.
			 * @param string $post_id Post ID.
			 */
			'classes'  => apply_filters(
				'jetpack_relatedposts_filter_post_css_classes',
				array(),
				$post->ID
			),
		);
	}

	/**
	 * Returns either the title or a small excerpt to use as title for post.
	 *
	 * @uses strip_shortcodes, wp_trim_words, __, apply_filters
	 *
	 * @param string $post_title   Post title.
	 * @param string $post_content Post content.
	 * @param int    $post_id Post ID.
	 *
	 * @return string
	 */
	protected function get_title( $post_title, $post_content, $post_id ) {
		if ( ! empty( $post_title ) ) {
			return wp_strip_all_tags(
				/** This filter is documented in core/src/wp-includes/post-template.php */
				apply_filters( 'the_title', $post_title, $post_id )
			);
		}

		$post_title = wp_trim_words( wp_strip_all_tags( strip_shortcodes( $post_content ) ), 5, '…' );
		if ( ! empty( $post_title ) ) {
			return $post_title;
		}

		return __( 'Untitled Post', 'jetpack' );
	}

	/**
	 * Returns a plain text post excerpt for title attribute of links.
	 *
	 * @param string $post_excerpt - the post excerpt.
	 * @param string $post_content - the post content.
	 * @uses strip_shortcodes, wp_strip_all_tags, wp_trim_words
	 * @return string
	 */
	protected function get_excerpt( $post_excerpt, $post_content ) {
		if ( empty( $post_excerpt ) ) {
			$excerpt = $post_content;
		} else {
			$excerpt = $post_excerpt;
		}

		return wp_trim_words( wp_strip_all_tags( strip_shortcodes( $excerpt ) ), 50, '…' );
	}

	/**
	 * Generates the thumbnail image to be used for the post. Uses the
	 * image as returned by Jetpack_PostImages::get_image()
	 *
	 * @param int $post_id - the post ID.
	 * @uses self::get_options, apply_filters, Jetpack_PostImages::get_image, Jetpack_PostImages::fit_image_url
	 * @return string
	 */
	protected function generate_related_post_image_params( $post_id ) {
		$image_params = array(
			'alt_text' => '',
			'src'      => '',
			'width'    => 0,
			'height'   => 0,
		);

		/**
		 * Filter the size of the Related Posts images.
		 *
		 * @module related-posts
		 *
		 * @since 2.8.0
		 *
		 * @param array array( 'width' => 350, 'height' => 200 ) Size of the images displayed below each Related Post.
		 */
		$thumbnail_size = apply_filters(
			'jetpack_relatedposts_filter_thumbnail_size',
			array(
				'width'  => 350,
				'height' => 200,
			)
		);
		if ( ! is_array( $thumbnail_size ) ) {
			$thumbnail_size = array(
				'width'  => (int) $thumbnail_size,
				'height' => (int) $thumbnail_size,
			);
		}

		// Try to get post image.
		if ( class_exists( 'Jetpack_PostImages' ) ) {
			$img_url    = '';
			$post_image = Jetpack_PostImages::get_image(
				$post_id,
				$thumbnail_size
			);

			if ( is_array( $post_image ) ) {
				$img_url = $post_image['src'];
			} elseif ( class_exists( 'Jetpack_Media_Summary' ) ) {
				$media = Jetpack_Media_Summary::get( $post_id );

				if ( is_array( $media ) && ! empty( $media['image'] ) ) {
					$img_url = $media['image'];
				}
			}

			if ( ! empty( $img_url ) ) {
				if ( ! empty( $post_image['alt_text'] ) ) {
					$image_params['alt_text'] = $post_image['alt_text'];
				} else {
					$image_params['alt_text'] = '';
				}
				$image_params['width']  = $thumbnail_size['width'];
				$image_params['height'] = $thumbnail_size['height'];
				$image_params['src']    = Jetpack_PostImages::fit_image_url(
					$img_url,
					$thumbnail_size['width'],
					$thumbnail_size['height']
				);
			}
		}

		return $image_params;
	}

	/**
	 * Returns the string UTF-8 encoded
	 *
	 * @param string $text - the text we want to convert.
	 * @return string
	 */
	protected function to_utf8( $text ) {
		if ( $this->convert_charset ) {
			return iconv( $this->blog_charset, 'UTF-8', $text );
		} else {
			return $text;
		}
	}

	/**
	 * =============================================
	 * PROTECTED UTILITY FUNCTIONS EXTENDED BY WPCOM
	 * =============================================
	 */

	/**
	 * Workhorse method to return array of related posts matched by Elasticsearch.
	 *
	 * @param int   $post_id - the ID of the post.
	 * @param int   $size - the size of the post.
	 * @param array $filters - filters.
	 * @uses wp_remote_post, is_wp_error, get_option, wp_remote_retrieve_body, get_post, add_query_arg, remove_query_arg, get_permalink, get_post_format, apply_filters
	 * @return array
	 */
	protected function get_related_posts( $post_id, $size, array $filters ) {
		$hits = $this->filter_non_public_posts(
			$this->get_related_post_ids(
				$post_id,
				$size,
				$filters
			)
		);

		/**
		 * Filter the Related Posts matched by Elasticsearch.
		 *
		 * @module related-posts
		 *
		 * @since 2.9.0
		 *
		 * @param array $hits Array of Post IDs matched by Elasticsearch.
		 * @param string $post_id Post ID of the post for which we are retrieving Related Posts.
		 */
		$hits = apply_filters( 'jetpack_relatedposts_filter_hits', $hits, $post_id );

		$related_posts = array();
		foreach ( $hits as $i => $hit ) {
			$related_posts[] = $this->get_related_post_data_for_post( $hit['id'], $i, $post_id );
		}
		return $related_posts;
	}

	/**
	 * Get array of related posts matched by Elasticsearch.
	 *
	 * @param int   $post_id - the post ID.
	 * @param int   $size - the size.
	 * @param array $filters - some filters.
	 * @uses wp_remote_post, is_wp_error, wp_remote_retrieve_body, get_post_meta, update_post_meta
	 * @return array
	 */
	protected function get_related_post_ids( $post_id, $size, array $filters ) {
		$now_ts         = time();
		$cache_meta_key = '_jetpack_related_posts_cache';

		$body = array(
			'size' => (int) $size,
		);

		if ( ! empty( $filters ) ) {
			$body['filter'] = array( 'and' => $filters );
		}

		// Build cache key.
		$cache_key = md5( serialize( $body ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- this is used for caching.

		// Load all cached values.
		if ( wp_using_ext_object_cache() ) {
			$transient_name = "{$cache_meta_key}_{$cache_key}_{$post_id}";
			$cache          = get_transient( $transient_name );
			if ( false !== $cache ) {
				return $cache;
			}
		} else {
			$cache = get_post_meta( $post_id, $cache_meta_key, true );

			if ( empty( $cache ) ) {
				$cache = array();
			}

			// Cache is valid! Return cached value.
			if ( isset( $cache[ $cache_key ] ) && is_array( $cache[ $cache_key ] ) && $cache[ $cache_key ]['expires'] > $now_ts ) {
				return $cache[ $cache_key ]['payload'];
			}
		}

		$user_agent = '';
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$user_agent = strtolower( filter_var( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) );
		}

		$response = wp_remote_post(
			"https://public-api.wordpress.com/rest/v1/sites/{$this->get_blog_id()}/posts/$post_id/related/",
			array(
				'timeout'    => 10,
				'user-agent' => "jetpack_related_posts, $user_agent",
				'sslverify'  => true,
				'body'       => $body,
			)
		);

		// Oh no... return nothing don't cache errors. Also, don't cache HTTP 409 conflict responses.
		if ( is_wp_error( $response ) || WP_Http::CONFLICT === wp_remote_retrieve_response_code( $response ) ) {
			if ( isset( $cache[ $cache_key ] ) && is_array( $cache[ $cache_key ] ) ) {
				return $cache[ $cache_key ]['payload']; // return stale.
			} else {
				return array();
			}
		}

		$results       = json_decode( wp_remote_retrieve_body( $response ), true );
		$related_posts = array();
		if ( is_array( $results ) && ! empty( $results['hits'] ) ) {
			foreach ( $results['hits'] as $hit ) {
				$related_posts[] = array(
					'id' => $hit['fields']['post_id'],
				);
			}
		}

		// An empty array might indicate no related posts or that posts
		// are not yet synced to WordPress.com, so we cache for only 1
		// minute in this case.
		if ( empty( $related_posts ) ) {
			$cache_ttl = 60;
		} else {
			$cache_ttl = 12 * HOUR_IN_SECONDS;
		}

		// Update cache.
		if ( wp_using_ext_object_cache() ) {
			set_transient( $transient_name, $related_posts, $cache_ttl );
		} else {
			// Copy all valid cache values.
			$new_cache = array();
			foreach ( $cache as $k => $v ) {
				if ( is_array( $v ) && $v['expires'] > $now_ts ) {
					$new_cache[ $k ] = $v;
				}
			}

			// Set new cache value.
			$cache_expires           = $cache_ttl + $now_ts;
			$new_cache[ $cache_key ] = array(
				'expires' => $cache_expires,
				'payload' => $related_posts,
			);
			update_post_meta( $post_id, $cache_meta_key, $new_cache );
		}

		return $related_posts;
	}

	/**
	 * Filter out any hits that are not public anymore.
	 *
	 * @param array $related_posts - the related posts.
	 * @uses get_post_stati, get_post_status
	 * @return array
	 */
	protected function filter_non_public_posts( array $related_posts ) {
		$public_stati = get_post_stati( array( 'public' => true ) );

		$filtered = array();
		foreach ( $related_posts as $hit ) {
			if ( in_array( get_post_status( $hit['id'] ), $public_stati, true ) ) {
				$filtered[] = $hit;
			}
		}
		return $filtered;
	}

	/**
	 * Generates a context for the related content (second line in related post output).
	 * Order of importance:
	 *   - First category (Not 'Uncategorized')
	 *   - First post tag
	 *   - Number of comments
	 *
	 * @param int $post_id - the post ID.
	 * @uses get_the_category, get_the_terms, get_comments_number, number_format_i18n, __, _n
	 * @return string
	 */
	protected function generate_related_post_context( $post_id ) {
		$categories = get_the_category( $post_id );
		if ( is_array( $categories ) ) {
			foreach ( $categories as $category ) {
				if ( 'uncategorized' !== $category->slug && '' !== trim( $category->name ) ) {
					$post_cat_context = sprintf(
						// Translators: The category or tag name.
						esc_html_x( 'In "%s"', 'in {category/tag name}', 'jetpack' ),
						$category->name
					);
					/**
					 * Filter the "In Category" line displayed in the post context below each Related Post.
					 *
					 * @module related-posts
					 *
					 * @since 3.2.0
					 *
					 * @param string $post_cat_context "In Category" line displayed in the post context below each Related Post.
					 * @param array $category Array containing information about the category.
					 */
					return apply_filters( 'jetpack_relatedposts_post_category_context', $post_cat_context, $category );
				}
			}
		}

		$tags = get_the_terms( $post_id, 'post_tag' );
		if ( is_array( $tags ) ) {
			foreach ( $tags as $tag ) {
				if ( '' !== trim( $tag->name ) ) {
					$post_tag_context = sprintf(
						// Translators: the category or tag name.
						_x( 'In "%s"', 'in {category/tag name}', 'jetpack' ),
						$tag->name
					);
					/**
					 * Filter the "In Tag" line displayed in the post context below each Related Post.
					 *
					 * @module related-posts
					 *
					 * @since 3.2.0
					 *
					 * @param string $post_tag_context "In Tag" line displayed in the post context below each Related Post.
					 * @param array $tag Array containing information about the tag.
					 */
					return apply_filters( 'jetpack_relatedposts_post_tag_context', $post_tag_context, $tag );
				}
			}
		}

		$comment_count = get_comments_number( $post_id );
		if ( $comment_count > 0 ) {
			return sprintf(
				// Translators: amount of comments.
				_n( 'With %s comment', 'With %s comments', $comment_count, 'jetpack' ),
				number_format_i18n( $comment_count )
			);
		}

		return __( 'Similar post', 'jetpack' );
	}

	/**
	 * Logs clicks for clickthrough analysis and related result tuning.
	 *
	 * @param int $post_id - the post ID.
	 * @param int $to_post_id - the to post ID.
	 * @param int $link_position - the link position.
	 */
	protected function log_click( $post_id, $to_post_id, $link_position ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	}

	/**
	 * Determines if the current post is able to use related posts.
	 *
	 * @uses self::get_options, is_admin, is_single, apply_filters
	 * @return bool
	 */
	protected function enabled_for_request() {
		$enabled = is_single()
			&& ! is_attachment()
			&& ! is_admin()
			&& ! is_embed()
			&& ( ! $this->allow_feature_toggle() || $this->get_option( 'enabled' ) );

		/**
		 * Filter the Enabled value to allow related posts to be shown on pages as well.
		 *
		 * @module related-posts
		 *
		 * @since 3.3.0
		 *
		 * @param bool $enabled Should Related Posts be enabled on the current page.
		 */
		return apply_filters( 'jetpack_relatedposts_filter_enabled_for_request', $enabled );
	}

	/**
	 * Adds filters.
	 *
	 * @uses self::enqueue_assets, self::setup_shortcode, add_filter
	 */
	protected function action_frontend_init_page() {
		$this->enqueue_assets( true, true );
		$this->setup_shortcode();

		add_filter( 'the_content', array( $this, 'filter_add_target_to_dom' ), 40 );
	}

	/**
	 * Determines if the scripts need be enqueued.
	 *
	 * @return bool
	 */
	protected function requires_scripts() {
		return (
			! ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) &&
			! has_block( 'jetpack/related-posts' ) &&
			! Blocks::is_fse_theme()
		);
	}

	/**
	 * Enqueues assets needed to do async loading of related posts.
	 *
	 * @param string $script - the script we're enqueing.
	 * @param string $style - the style we're enqueing.
	 *
	 * @uses wp_enqueue_script, wp_enqueue_style, plugins_url
	 */
	protected function enqueue_assets( $script, $style ) {
		$dependencies = is_customize_preview() ? array( 'customize-base' ) : array();
		// Do not enqueue scripts unless they are required.
		if ( $script && $this->requires_scripts() ) {
			wp_enqueue_script(
				'jetpack_related-posts',
				Assets::get_file_url_for_environment(
					'_inc/build/related-posts/related-posts.min.js',
					'modules/related-posts/related-posts.js'
				),
				$dependencies,
				self::VERSION,
				false
			);
			$related_posts_js_options = array(
				/**
				 * Filter each Related Post Heading structure.
				 *
				 * @since 4.0.0
				 *
				 * @param string $str Related Post Heading structure. Default to h4.
				 */
				'post_heading' => apply_filters( 'jetpack_relatedposts_filter_post_heading', esc_attr( 'h4' ) ),
			);
			wp_localize_script( 'jetpack_related-posts', 'related_posts_js_options', $related_posts_js_options );
		}
		if ( $style ) {
			wp_enqueue_style( 'jetpack_related-posts', plugins_url( 'related-posts.css', __FILE__ ), array(), self::VERSION );
			wp_style_add_data( 'jetpack_related-posts', 'rtl', 'replace' );
			add_action( 'amp_post_template_css', array( $this, 'render_amp_reader_mode_css' ) );
		}
	}

	/**
	 * Render AMP's reader mode CSS.
	 */
	public function render_amp_reader_mode_css() {
		echo file_get_contents( __DIR__ . '/related-posts.css' );  // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- this is loading a CSS file.
	}

	/**
	 * Sets up the shortcode processing.
	 *
	 * @uses add_filter, add_shortcode
	 */
	protected function setup_shortcode() {
		add_filter( 'the_content', array( $this, 'test_for_shortcode' ), 0 );

		add_shortcode( self::SHORTCODE, array( $this, 'get_client_rendered_html' ) );
	}

	/**
	 * Return status of related posts toggle.
	 */
	protected function allow_feature_toggle() {
		if ( null === $this->allow_feature_toggle ) {
			/**
			 * Filter the display of the Related Posts toggle in Settings > Reading.
			 *
			 * @module related-posts
			 *
			 * @since 2.8.0
			 *
			 * @param bool $allow_feature_toggle Display a feature toggle. Default to false.
			 */
			$this->allow_feature_toggle = apply_filters( 'jetpack_relatedposts_filter_allow_feature_toggle', false );
		}
		return $this->allow_feature_toggle;
	}

	/**
	 * ===================================================
	 * FUNCTIONS EXPOSING RELATED POSTS IN THE WP REST API
	 * ===================================================
	 */

	/**
	 * Add Related Posts to the REST API Post response.
	 *
	 * @since 4.4.0
	 *
	 * @action rest_api_init
	 * @uses register_rest_field, self::rest_get_related_posts
	 */
	public function rest_register_related_posts() {
		/** This filter is already documented in class.json-api-endpoints.php */
		$post_types = apply_filters( 'rest_api_allowed_post_types', array( 'post', 'page', 'revision' ) );
		foreach ( $post_types as $post_type ) {
			register_rest_field(
				$post_type,
				'jetpack-related-posts',
				array(
					'get_callback'    => array( $this, 'rest_get_related_posts' ),
					'update_callback' => null,
					'schema'          => null,
				)
			);
		}
	}

	/**
	 * Build an array of Related Posts.
	 * By default returns cached results that are stored for up to 12 hours.
	 *
	 * @since 4.4.0
	 *
	 * @param array $object Details of current post.
	 *
	 * @uses self::get_for_post_id
	 *
	 * @return array
	 */
	public function rest_get_related_posts( $object ) {
		return $this->get_for_post_id( $object['id'], array( 'size' => 6 ) );
	}
}

/**
 * The raw related posts class can be used by other plugins or themes
 * to get related content. This class wraps the existing RelatedPosts
 * logic thus we never want to add anything to the DOM or do anything
 * for event hooks. We will also not present any settings for this
 * class and keep it enabled as calls to this class are done
 * programmatically.
 */
class Jetpack_RelatedPosts_Raw extends Jetpack_RelatedPosts { //phpcs:ignore Generic.Classes.OpeningBraceSameLine.ContentAfterBrace, Generic.Files.OneObjectStructurePerFile.MultipleFound

	/**
	 * The query name we want to look up.
	 *
	 * @var string
	 */
	protected $query_name;

	/**
	 * Allows callers of this class to tag each query with a unique name for tracking purposes.
	 *
	 * @param string $name - the name of the query.
	 * @return Jetpack_RelatedPosts_Raw
	 */
	public function set_query_name( $name ) {
		$this->query_name = (string) $name;
		return $this;
	}

	/**
	 * Initialize admin.
	 */
	public function action_admin_init() {}

	/**
	 * Initialize front end.
	 */
	public function action_frontend_init() {}

	/**
	 * Get options.
	 */
	public function get_options() {
		return array(
			'enabled' => true,
		);
	}

	/**
	 * Workhorse method to return array of related posts ids matched by Elasticsearch.
	 *
	 * @param int   $post_id - the post ID.
	 * @param int   $size - size of the post.
	 * @param array $filters - filters we're using.
	 * @uses wp_remote_post, is_wp_error, wp_remote_retrieve_body
	 * @return array
	 */
	protected function get_related_posts( $post_id, $size, array $filters ) {
		$hits = $this->filter_non_public_posts(
			$this->get_related_post_ids(
				$post_id,
				$size,
				$filters
			)
		);

		/** This filter is already documented in modules/related-posts/related-posts.php */
		$hits = apply_filters( 'jetpack_relatedposts_filter_hits', $hits, $post_id );

		return $hits;
	}
}
