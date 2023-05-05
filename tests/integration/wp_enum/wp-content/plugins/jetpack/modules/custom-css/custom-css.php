<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;

/**
 * Alternate Custom CSS source for 4.7 compat.
 *
 * @since 4.4.2
 *
 * @package automattic/jetpack
 */

/**
 * Class Jetpack_Custom_CSS_Enhancements
 */
class Jetpack_Custom_CSS_Enhancements {

	/**
	 * Set up the actions and filters needed for our compatability layer on top of core's Custom CSS implementation.
	 */
	public static function add_hooks() {
		add_action( 'init', array( __CLASS__, 'init' ) );
		add_action( 'customize_controls_enqueue_scripts', array( __CLASS__, 'customize_controls_enqueue_scripts' ) );
		add_action( 'customize_register', array( __CLASS__, 'customize_register' ) );
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), 20, 2 );
		add_action( 'customize_preview_init', array( __CLASS__, 'customize_preview_init' ) );
		add_filter( '_wp_post_revision_fields', array( __CLASS__, 'wp_post_revision_fields' ), 10, 2 );
		add_action( 'load-revision.php', array( __CLASS__, 'load_revision_php' ) );

		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'wp_enqueue_scripts' ) );

		// Handle Sass/LESS.
		add_filter( 'customize_value_custom_css', array( __CLASS__, 'customize_value_custom_css' ), 10, 2 );
		add_filter( 'customize_update_custom_css_post_content_args', array( __CLASS__, 'customize_update_custom_css_post_content_args' ), 10, 3 );
		add_filter( 'update_custom_css_data', array( __CLASS__, 'update_custom_css_data' ), 10, 2 );

		// Stuff for stripping out the theme's default stylesheet...
		add_filter( 'stylesheet_uri', array( __CLASS__, 'style_filter' ) );
		add_filter( 'safecss_skip_stylesheet', array( __CLASS__, 'preview_skip_stylesheet' ) );

		// Stuff for overriding content width...
		add_action( 'customize_preview_init', array( __CLASS__, 'preview_content_width' ) );
		add_filter( 'jetpack_content_width', array( __CLASS__, 'jetpack_content_width' ) );
		add_filter( 'editor_max_image_size', array( __CLASS__, 'editor_max_image_size' ), 10, 3 );
		add_action( 'template_redirect', array( __CLASS__, 'set_content_width' ) );
		add_action( 'admin_init', array( __CLASS__, 'set_content_width' ) );
	}

	/**
	 * Things that we do on init.
	 */
	public static function init() {

		wp_register_style( 'jetpack-codemirror', plugins_url( 'custom-css/css/codemirror.css', __FILE__ ), array(), '20120905' );
		wp_register_style( 'jetpack-customizer-css', plugins_url( 'custom-css/css/customizer-control.css', __FILE__ ), array(), '20140728' );
		wp_register_script( 'jetpack-codemirror', plugins_url( 'custom-css/js/codemirror.min.js', __FILE__ ), array(), '3.16', true );

		$src = Assets::get_file_url_for_environment(
			'_inc/build/custom-css/custom-css/js/core-customizer-css.core-4.9.min.js',
			'modules/custom-css/custom-css/js/core-customizer-css.core-4.9.js'
		);
		wp_register_script(
			'jetpack-customizer-css',
			$src,
			array(
				'jquery',
				'customize-controls',
				'underscore',
			),
			JETPACK__VERSION,
			true
		);

		wp_register_script(
			'jetpack-customizer-css-preview',
			Assets::get_file_url_for_environment(
				'_inc/build/custom-css/custom-css/js/core-customizer-css-preview.min.js',
				'modules/custom-css/custom-css/js/core-customizer-css-preview.js'
			),
			array( 'jquery', 'customize-selective-refresh' ),
			JETPACK__VERSION,
			true
		);

		remove_action( 'wp_head', 'wp_custom_css_cb', 11 ); // 4.7.0 had it at 11, 4.7.1 moved it to 101.
		remove_action( 'wp_head', 'wp_custom_css_cb', 101 );
		add_action( 'wp_head', array( __CLASS__, 'wp_custom_css_cb' ), 101 );

		if ( isset( $_GET['custom-css'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site.
			self::print_linked_custom_css();
		}
	}

	/**
	 * Things that we do on init when the Customize Preview is loading.
	 */
	public static function customize_preview_init() {
		add_filter( 'wp_get_custom_css', array( __CLASS__, 'customize_preview_wp_get_custom_css' ) );
	}

	/**
	 * Print the current Custom CSS. This is for linking instead of printing directly.
	 */
	public static function print_linked_custom_css() {
		header( 'Content-type: text/css' );
		header( 'Expires: ' . gmdate( 'D, d M Y H:i:s', time() + YEAR_IN_SECONDS ) . ' GMT' );
		echo wp_get_custom_css(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	/**
	 * Re-map the Edit CSS capability.
	 *
	 * Core, by default, restricts this to users that have `unfiltered_html` which
	 * would make the feature unusable in multi-site by non-super-admins, due to Core
	 * not shipping any solid sanitization.
	 *
	 * We're expanding who can use it, and then conditionally applying CSSTidy
	 * sanitization to users that do not have the `unfiltered_html` capability.
	 *
	 * @param array  $caps Returns the user's actual capabilities.
	 * @param string $cap  Capability name.
	 *
	 * @return array $caps
	 */
	public static function map_meta_cap( $caps, $cap ) {
		if ( 'edit_css' === $cap ) {
			$caps = array( 'edit_theme_options' );
		}
		return $caps;
	}

	/**
	 * Shows Preprocessor code in the Revisions screen, and ensures that post_content_filtered
	 * is maintained on revisions
	 *
	 * @param array $fields  Post fields pertinent to revisions.
	 * @param array $post    A post array being processed for insertion as a post revision.
	 *
	 * @return array $fields Modified array to include post_content_filtered.
	 */
	public static function wp_post_revision_fields( $fields, $post ) {
		// None of the fields in $post are required to be passed in this filter.
		if ( ! isset( $post['post_type'], $post['ID'] ) ) {
			return $fields;
		}

		// If we're passed in a revision, go get the main post instead.
		if ( 'revision' === $post['post_type'] ) {
			$main_post_id = wp_is_post_revision( $post['ID'] );
			$post         = get_post( $main_post_id, ARRAY_A );
		}
		if ( 'custom_css' === $post['post_type'] ) {
			$fields['post_content']          = __( 'CSS', 'jetpack' );
			$fields['post_content_filtered'] = __( 'Preprocessor', 'jetpack' );
		}
		return $fields;
	}

	/**
	 * Get the published custom CSS post.
	 *
	 * @param string $stylesheet Optional. A theme object stylesheet name. Defaults to the current theme.
	 * @return WP_Post|null
	 */
	public static function get_css_post( $stylesheet = '' ) {
		return wp_get_custom_css_post( $stylesheet );
	}

	/**
	 * Override Core's `wp_custom_css_cb` method to provide linking to custom css.
	 */
	public static function wp_custom_css_cb() {
		$styles = wp_get_custom_css();
		if ( ! $styles ) {
			return;
		}

		$should_embed = strlen( $styles ) < 2000;
		/** This filter is documented in projects/plugins/jetpack/modules/custom-css/custom-css.php */
		$should_embed = apply_filters( 'safecss_embed_style', $should_embed, $styles );

		if ( $should_embed || is_customize_preview() ) {
			printf(
				'<style type="text/css" id="wp-custom-css">%1$s</style>',
				wp_strip_all_tags( $styles ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			);
		} else {
			// Add a cache buster to the url.
			$url = home_url( '/' );
			$url = add_query_arg( 'custom-css', substr( md5( $styles ), -10 ), $url );

			printf(
				'<link rel="stylesheet" type="text/css" id="wp-custom-css" href="%1$s" />', // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet
				esc_url( $url )
			);
		}
	}

	/**
	 * Get the ID of a Custom CSS post tying to a given stylesheet.
	 *
	 * @param string $stylesheet Stylesheet name.
	 *
	 * @return int $post_id Post ID.
	 */
	public static function post_id( $stylesheet = '' ) {
		$post = self::get_css_post( $stylesheet );
		if ( $post instanceof WP_Post ) {
			return $post->ID;
		}
		return 0;
	}

	/**
	 * Partial for use in the Customizer.
	 */
	public static function echo_custom_css_partial() {
		echo wp_get_custom_css(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Admin page!
	 *
	 * This currently has two main uses -- firstly to display the css for an inactive
	 * theme if there are no revisions attached it to a legacy bug, and secondly to
	 * handle folks that have bookmarkes in their browser going to the old page for
	 * managing Custom CSS in Jetpack.
	 *
	 * If we ever add back in a non-Customizer CSS editor, this would be the place.
	 */
	public static function admin_page() {
		$post       = null;
		$stylesheet = null;
		if ( isset( $_GET['id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site.
			$post_id = absint( $_GET['id'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site
			$post    = get_post( $post_id );
			if ( $post instanceof WP_Post && 'custom_css' === $post->post_type ) {
				$stylesheet = $post->post_title;
			}
		}
		?>
		<div class="wrap">
			<?php self::revisions_switcher_box( $stylesheet ); ?>
			<h1>
				<?php
				if ( $post ) {
					printf( 'Custom CSS for &#8220;%1$s&#8221;', wp_get_theme( $stylesheet )->Name ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				} else {
					esc_html_e( 'Custom CSS', 'jetpack' );
				}
				if ( current_user_can( 'customize' ) ) {
					printf(
						' <a class="page-title-action hide-if-no-customize" href="%1$s">%2$s</a>',
						esc_url( self::customizer_link() ),
						esc_html__( 'Manage with Live Preview', 'jetpack' )
					);
				}
				?>
			</h1>
			<p><?php esc_html_e( 'Custom CSS is now managed in the Customizer.', 'jetpack' ); ?></p>
			<?php if ( $post ) : ?>
				<div class="revisions">
					<h3><?php esc_html_e( 'CSS', 'jetpack' ); ?></h3>
					<textarea class="widefat" readonly><?php echo esc_textarea( $post->post_content ); ?></textarea>
					<?php if ( $post->post_content_filtered ) : ?>
						<h3><?php esc_html_e( 'Preprocessor', 'jetpack' ); ?></h3>
						<textarea class="widefat" readonly><?php echo esc_textarea( $post->post_content_filtered ); ?></textarea>
					<?php endif; ?>
				</div>
			<?php endif; ?>
		</div>

		<style>
			.other-themes-wrap {
				float: right;
				background-color: #fff;
				-webkit-box-shadow: 0 1px 3px rgba(0,0,0,0.1);
				box-shadow: 0 1px 3px rgba(0,0,0,0.1);
				padding: 5px 10px;
				margin-bottom: 10px;
			}
			.other-themes-wrap label {
				display: block;
				margin-bottom: 10px;
			}
			.other-themes-wrap select {
				float: left;
				width: 77%;
			}
			.other-themes-wrap button {
				float: right;
				width: 20%;
			}
			.revisions {
				clear: both;
			}
			.revisions textarea {
				min-height: 300px;
				background: #fff;
			}
		</style>
		<script>
			(function($){
				var $switcher = $('.other-themes-wrap');
				$switcher.find('button').on('click', function(e){
					e.preventDefault();
					if ( $switcher.find('select').val() ) {
						window.location.href = $switcher.find('select').val();
					}
				});
			})(jQuery);
		</script>
		<?php
	}

	/**
	 * Build the URL to deep link to the Customizer.
	 *
	 * You can modify the return url via $args.
	 *
	 * @param array $args Array of parameters.
	 * @return string
	 */
	public static function customizer_link( $args = array() ) {
		$args = wp_parse_args(
			$args,
			array(
				'return_url' => isset( $_SERVER['REQUEST_URI'] ) ? rawurlencode( filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ) ) : '',
			)
		);

		return add_query_arg(
			array(
				array(
					'autofocus' => array(
						'section' => 'custom_css',
					),
				),
				'return' => $args['return_url'],
			),
			admin_url( 'customize.php' )
		);
	}

	/**
	 * Handle the enqueueing and localizing for scripts to be used in the Customizer.
	 */
	public static function customize_controls_enqueue_scripts() {
		wp_enqueue_style( 'jetpack-customizer-css' );
		wp_enqueue_script( 'jetpack-customizer-css' );

		$content_help = __( 'Set a different media width for full size images.', 'jetpack' );
		if ( ! empty( $GLOBALS['content_width'] ) ) {
			$content_help .= sprintf(
				// translators: the theme name and then the default width.
				_n( ' The default media width for the <strong>%1$s</strong> theme is %2$d pixel.', ' The default media width for the <strong>%1$s</strong> theme is %2$d pixels.', (int) $GLOBALS['content_width'], 'jetpack' ),
				wp_get_theme()->Name,
				(int) $GLOBALS['content_width']
			);
		}

		wp_localize_script(
			'jetpack-customizer-css',
			'_jp_css_settings',
			array(
				/** This filter is documented in modules/custom-css/custom-css.php */
				'useRichEditor'        => ! jetpack_is_mobile() && apply_filters( 'safecss_use_ace', true ),
				'areThereCssRevisions' => self::are_there_css_revisions(),
				'revisionsUrl'         => self::get_revisions_url(),
				'cssHelpUrl'           => '//en.support.wordpress.com/custom-design/editing-css/',
				'l10n'                 => array(
					'mode'           => __( 'Start Fresh', 'jetpack' ),
					'mobile'         => __( 'On Mobile', 'jetpack' ),
					'contentWidth'   => $content_help,
					'revisions'      => _x( 'See full history', 'Toolbar button to see full CSS revision history', 'jetpack' ),
					'css_help_title' => _x( 'Help', 'Toolbar button to get help with custom CSS', 'jetpack' ),
				),
			)
		);
	}

	/**
	 * Check whether there are CSS Revisions for a given theme.
	 *
	 * Going forward, there should always be, but this was necessitated
	 * early on by https://core.trac.wordpress.org/ticket/30854
	 *
	 * @param string $stylesheet Stylesheet name.
	 *
	 * @return bool|null|WP_Post
	 */
	public static function are_there_css_revisions( $stylesheet = '' ) {
		$post = wp_get_custom_css_post( $stylesheet );
		if ( empty( $post ) ) {
			return $post;
		}
		return (bool) wp_get_post_revisions( $post );
	}

	/**
	 * Core doesn't have a function to get the revisions url for a given post ID.
	 *
	 * @param string $stylesheet Stylesheet name.
	 *
	 * @return null|string|void
	 */
	public static function get_revisions_url( $stylesheet = '' ) {
		$post = wp_get_custom_css_post( $stylesheet );

		// If we have any currently saved customizations...
		if ( $post instanceof WP_Post ) {
			$revisions = wp_get_post_revisions( $post->ID, array( 'posts_per_page' => 1 ) );
			if ( empty( $revisions ) || is_wp_error( $revisions ) ) {
				return admin_url( 'themes.php?page=editcss' );
			}
			$revision = reset( $revisions );
			return get_edit_post_link( $revision->ID );
		}

		return admin_url( 'themes.php?page=editcss' );
	}

	/**
	 * Get a map of all theme names and theme stylesheets for mapping stuff.
	 *
	 * @return array
	 */
	public static function get_themes() {
		$themes = wp_get_themes( array( 'errors' => null ) );
		$all    = array();
		foreach ( $themes as $theme ) {
			$all[ $theme->name ] = $theme->stylesheet;
		}
		return $all;
	}

	/**
	 * When we need to get all themes that have Custom CSS saved.
	 *
	 * @return array
	 */
	public static function get_all_themes_with_custom_css() {
		$themes     = self::get_themes();
		$custom_css = get_posts(
			array(
				'post_type'   => 'custom_css',
				'post_status' => get_post_stati(),
				'number'      => -1,
				'order'       => 'DESC',
				'orderby'     => 'modified',
			)
		);
		$return     = array();

		foreach ( $custom_css as $post ) {
			$stylesheet = $post->post_title;
			$label      = array_search( $stylesheet, $themes, true );

			if ( ! $label ) {
				continue;
			}

			$return[ $stylesheet ] = array(
				'label' => $label,
				'post'  => $post,
			);
		}

		return $return;
	}

	/**
	 * Handle the enqueueing of scripts for customize previews.
	 */
	public static function wp_enqueue_scripts() {
		if ( is_customize_preview() ) {
			wp_enqueue_script( 'jetpack-customizer-css-preview' );
			wp_localize_script(
				'jetpack-customizer-css-preview',
				'jpCustomizerCssPreview',
				array(
					/** This filter is documented in modules/custom-css/custom-css.php */
					'preprocessors' => apply_filters( 'jetpack_custom_css_preprocessors', array() ),
				)
			);
		}
	}

	/**
	 * Sanitize the CSS for users without `unfiltered_html`.
	 *
	 * @param string $css  Input CSS.
	 * @param array  $args Array of CSS options.
	 *
	 * @return mixed|string
	 */
	public static function sanitize_css( $css, $args = array() ) {
		$args = wp_parse_args(
			$args,
			array(
				'force'        => false,
				'preprocessor' => null,
			)
		);

		if ( $args['force'] || ! current_user_can( 'unfiltered_html' ) ) {

			$warnings = array();

			safecss_class();
			$csstidy           = new csstidy();
			$csstidy->optimise = new safecss( $csstidy );

			$csstidy->set_cfg( 'remove_bslash', false );
			$csstidy->set_cfg( 'compress_colors', false );
			$csstidy->set_cfg( 'compress_font-weight', false );
			$csstidy->set_cfg( 'optimise_shorthands', 0 );
			$csstidy->set_cfg( 'remove_last_;', false );
			$csstidy->set_cfg( 'case_properties', false );
			$csstidy->set_cfg( 'discard_invalid_properties', true );
			$csstidy->set_cfg( 'css_level', 'CSS3.0' );
			$csstidy->set_cfg( 'preserve_css', true );
			$csstidy->set_cfg( 'template', __DIR__ . '/csstidy/wordpress-standard.tpl' );

			// Test for some preg_replace stuff.
			$prev = $css;
			$css  = preg_replace( '/\\\\([0-9a-fA-F]{4})/', '\\\\\\\\$1', $css );
			// prevent content: '\3434' from turning into '\\3434'.
			$css = str_replace( array( '\'\\\\', '"\\\\' ), array( '\'\\', '"\\' ), $css );
			if ( $css !== $prev ) {
				$warnings[] = 'preg_replace found stuff';
			}

			// Some people put weird stuff in their CSS, KSES tends to be greedy.
			$css = str_replace( '<=', '&lt;=', $css );

			// Test for some kses stuff.
			$prev = $css;
			// Why KSES instead of strip_tags?  Who knows?
			$css = wp_kses_split( $css, array(), array() );
			$css = str_replace( '&gt;', '>', $css ); // kses replaces lone '>' with &gt;
			// Why both KSES and strip_tags?  Because we just added some '>'.
			$css = strip_tags( $css ); // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- scared to update this to wp_strip_all_tags since we're building a CSS file here.

			if ( $css !== $prev ) {
				$warnings[] = 'kses found stuff';
			}

			// if we're not using a preprocessor.
			if ( ! $args['preprocessor'] ) {

				/** This action is documented in modules/custom-css/custom-css.php */
				do_action( 'safecss_parse_pre', $csstidy, $css, $args );

				$csstidy->parse( $css );

				/** This action is documented in modules/custom-css/custom-css.php */
				do_action( 'safecss_parse_post', $csstidy, $warnings, $args );

				$css = $csstidy->print->plain();
			}
		}
		return $css;
	}

	/**
	 * Override $content_width in customizer previews.
	 */
	public static function preview_content_width() {
		global $wp_customize;
		if ( ! is_customize_preview() ) {
			return;
		}

		$setting = $wp_customize->get_setting( 'jetpack_custom_css[content_width]' );
		if ( ! $setting ) {
			return;
		}

		$customized_content_width = (int) $setting->post_value();
		if ( ! empty( $customized_content_width ) ) {
			$GLOBALS['content_width'] = $customized_content_width;
		}
	}

	/**
	 * Filter the current theme's stylesheet for potentially nullifying it.
	 *
	 * @param string $current Stylesheet URI for the current theme/child theme.
	 *
	 * @return mixed|void
	 */
	public static function style_filter( $current ) {
		if ( is_admin() ) {
			return $current;
		} elseif ( self::is_freetrial() && ( ! self::is_preview() || ! current_user_can( 'switch_themes' ) ) ) {
			return $current;
		} elseif ( self::skip_stylesheet() ) {
			/** This filter is documented in modules/custom-css/custom-css.php */
			return apply_filters( 'safecss_style_filter_url', plugins_url( 'custom-css/css/blank.css', __FILE__ ) );
		}

		return $current;
	}

	/**
	 * Determine whether or not we should have the theme skip its main stylesheet.
	 *
	 * @return mixed The truthiness of this value determines whether the stylesheet should be skipped.
	 */
	public static function skip_stylesheet() {
		/** This filter is documented in modules/custom-css/custom-css.php */
		$skip_stylesheet = apply_filters( 'safecss_skip_stylesheet', null );
		if ( $skip_stylesheet !== null ) {
			return $skip_stylesheet;
		}

		$jetpack_custom_css = get_theme_mod( 'jetpack_custom_css', array() );
		if ( isset( $jetpack_custom_css['replace'] ) ) {
			return $jetpack_custom_css['replace'];
		}

		return false;
	}

	/**
	 * Override $content_width in customizer previews.
	 *
	 * Runs on `safecss_skip_stylesheet` filter.
	 *
	 * @param bool $skip_value Should the stylesheet be skipped.
	 *
	 * @return null|bool
	 */
	public static function preview_skip_stylesheet( $skip_value ) {
		global $wp_customize;
		if ( ! is_customize_preview() ) {
			return $skip_value;
		}

		$setting = $wp_customize->get_setting( 'jetpack_custom_css[replace]' );
		if ( ! $setting ) {
			return $skip_value;
		}

		$customized_replace = $setting->post_value();
		if ( null !== $customized_replace ) {
			return $customized_replace;
		}

		return $skip_value;
	}

	/**
	 * Add Custom CSS section and controls.
	 *
	 * @param WP_Customize_Manager $wp_customize WP_Customize_Manager instance.
	 */
	public static function customize_register( $wp_customize ) {

		/**
		 * SETTINGS.
		 */

		$wp_customize->add_setting(
			'jetpack_custom_css[preprocessor]',
			array(
				'default'           => '',
				'transport'         => 'postMessage',
				'sanitize_callback' => array( __CLASS__, 'sanitize_preprocessor' ),
			)
		);

		$wp_customize->add_setting(
			'jetpack_custom_css[replace]',
			array(
				'default'   => false,
				'transport' => 'refresh',
			)
		);

		$wp_customize->add_setting(
			'jetpack_custom_css[content_width]',
			array(
				'default'           => '',
				'transport'         => 'refresh',
				'sanitize_callback' => array( __CLASS__, 'intval_base10' ),
			)
		);

		// Add custom sanitization to the core css customizer setting.
		foreach ( $wp_customize->settings() as $setting ) {
			if ( $setting instanceof WP_Customize_Custom_CSS_Setting ) {
				add_filter( "customize_sanitize_{$setting->id}", array( __CLASS__, 'sanitize_css_callback' ), 10, 2 );
			}
		}

		/**
		 * CONTROLS.
		 */

		// Overwrite or Tweak the Core Control.
		$core_custom_css = $wp_customize->get_control( 'custom_css' );
		if ( $core_custom_css ) {
			if ( $core_custom_css instanceof WP_Customize_Code_Editor_Control ) {
				// In WP 4.9, we let the Core CodeMirror control keep running the show, but hook into it to tweak stuff.
				$types        = array(
					'default' => 'text/css',
					'less'    => 'text/x-less',
					'sass'    => 'text/x-scss',
				);
				$preprocessor = $wp_customize->get_setting( 'jetpack_custom_css[preprocessor]' )->value();
				if ( isset( $types[ $preprocessor ] ) ) {
					$core_custom_css->code_type = $types[ $preprocessor ];
				}
			} else {
				// Core < 4.9 Fallback
				$core_custom_css->type = 'jetpackCss';
			}
		}

		$wp_customize->selective_refresh->add_partial(
			'custom_css',
			array(
				'type'                => 'custom_css',
				'selector'            => '#wp-custom-css',
				'container_inclusive' => false,
				'fallback_refresh'    => false,
				'settings'            => array(
					'custom_css[' . $wp_customize->get_stylesheet() . ']',
					'jetpack_custom_css[preprocessor]',
				),
				'render_callback'     => array( __CLASS__, 'echo_custom_css_partial' ),
			)
		);

		$wp_customize->add_control(
			'wpcom_custom_css_content_width_control',
			array(
				'type'     => 'text',
				'label'    => __( 'Media Width', 'jetpack' ),
				'section'  => 'custom_css',
				'settings' => 'jetpack_custom_css[content_width]',
			)
		);

		$wp_customize->add_control(
			'jetpack_css_mode_control',
			array(
				'type'     => 'checkbox',
				'label'    => __( 'Don\'t use the theme\'s original CSS.', 'jetpack' ),
				'section'  => 'custom_css',
				'settings' => 'jetpack_custom_css[replace]',
			)
		);

		/**
		 * An action to grab on to if another Jetpack Module would like to add its own controls.
		 *
		 * @module custom-css
		 *
		 * @since 4.4.2
		 *
		 * @param $wp_customize The WP_Customize object.
		 */
		do_action( 'jetpack_custom_css_customizer_controls', $wp_customize );

		/** This filter is documented in modules/custom-css/custom-css.php */
		$preprocessors = apply_filters( 'jetpack_custom_css_preprocessors', array() );
		if ( ! empty( $preprocessors ) ) {
			$preprocessor_choices = array(
				'' => __( 'None', 'jetpack' ),
			);

			foreach ( $preprocessors as $preprocessor_key => $processor ) {
				$preprocessor_choices[ $preprocessor_key ] = $processor['name'];
			}

			$wp_customize->add_control(
				'jetpack_css_preprocessors_control',
				array(
					'type'     => 'select',
					'choices'  => $preprocessor_choices,
					'label'    => __( 'Preprocessor', 'jetpack' ),
					'section'  => 'custom_css',
					'settings' => 'jetpack_custom_css[preprocessor]',
				)
			);
		}
	}

	/**
	 * The callback to handle sanitizing the CSS. Takes different arguments, hence the proxy function.
	 *
	 * @param mixed $css Value of the setting.
	 *
	 * @return mixed|string
	 */
	public static function sanitize_css_callback( $css ) {
		global $wp_customize;
		return self::sanitize_css(
			$css,
			array(
				'preprocessor' => $wp_customize->get_setting( 'jetpack_custom_css[preprocessor]' )->value(),
			)
		);
	}

	/**
	 * Flesh out for wpcom.
	 *
	 * @todo
	 *
	 * @return bool
	 */
	public static function is_freetrial() {
		return false;
	}

	/**
	 * Flesh out for wpcom.
	 *
	 * @todo
	 *
	 * @return bool
	 */
	public static function is_preview() {
		return false;
	}

	/**
	 * Output the custom css for customize preview.
	 *
	 * @param string $css Custom CSS content.
	 *
	 * @return mixed
	 */
	public static function customize_preview_wp_get_custom_css( $css ) {
		global $wp_customize;

		$preprocessor = $wp_customize->get_setting( 'jetpack_custom_css[preprocessor]' )->value();

		// If it's empty, just return.
		if ( empty( $preprocessor ) ) {
			return $css;
		}

		/** This filter is documented in modules/custom-css/custom-css.php */
		$preprocessors = apply_filters( 'jetpack_custom_css_preprocessors', array() );
		if ( isset( $preprocessors[ $preprocessor ] ) ) {
			return call_user_func( $preprocessors[ $preprocessor ]['callback'], $css );
		}

		return $css;
	}

	/**
	 * Add CSS preprocessing to our CSS if it is supported.
	 *
	 * @param mixed                $css     Value of the setting.
	 * @param WP_Customize_Setting $setting WP_Customize_Setting instance.
	 *
	 * @return string
	 */
	public static function customize_value_custom_css( $css, $setting ) {
		// Find the current preprocessor.
		$jetpack_custom_css = get_theme_mod( 'jetpack_custom_css', array() );
		if ( isset( $jetpack_custom_css['preprocessor'] ) ) {
			$preprocessor = $jetpack_custom_css['preprocessor'];
		}

		// If it's not supported, just return.
		/** This filter is documented in modules/custom-css/custom-css.php */
		$preprocessors = apply_filters( 'jetpack_custom_css_preprocessors', array() );
		if ( ! isset( $preprocessors[ $preprocessor ] ) ) {
			return $css;
		}

		// Swap it for the `post_content_filtered` instead.
		$post = wp_get_custom_css_post( $setting->stylesheet );
		if ( $post && ! empty( $post->post_content_filtered ) ) {
			$css = $post->post_content_filtered;
		}

		return $css;
	}

	/**
	 * Store the original pre-processed CSS in `post_content_filtered`
	 * and then store processed CSS in `post_content`.
	 *
	 * @param array  $args Content post args.
	 * @param string $css  Original CSS being updated.
	 *
	 * @return mixed
	 */
	public static function customize_update_custom_css_post_content_args( $args, $css ) {
		// Find the current preprocessor.
		$jetpack_custom_css = get_theme_mod( 'jetpack_custom_css', array() );
		if ( empty( $jetpack_custom_css['preprocessor'] ) ) {
			return $args;
		}

		$preprocessor = $jetpack_custom_css['preprocessor'];
		/** This filter is documented in modules/custom-css/custom-css.php */
		$preprocessors = apply_filters( 'jetpack_custom_css_preprocessors', array() );

		// If it's empty, just return.
		if ( empty( $preprocessor ) ) {
			return $args;
		}

		if ( isset( $preprocessors[ $preprocessor ] ) ) {
			$args['post_content_filtered'] = $css;
			$args['post_content']          = call_user_func( $preprocessors[ $preprocessor ]['callback'], $css );
		}

		return $args;
	}

	/**
	 * Filter to handle the processing of preprocessed css on save.
	 *
	 * @param array $args Custom CSS options.
	 *
	 * @return mixed
	 */
	public static function update_custom_css_data( $args ) {
		// Find the current preprocessor.
		$jetpack_custom_css = get_theme_mod( 'jetpack_custom_css', array() );
		if ( empty( $jetpack_custom_css['preprocessor'] ) ) {
			return $args;
		}

		/** This filter is documented in modules/custom-css/custom-css.php */
		$preprocessors = apply_filters( 'jetpack_custom_css_preprocessors', array() );
		$preprocessor  = $jetpack_custom_css['preprocessor'];

		// If we have a preprocessor specified ...
		if ( isset( $preprocessors[ $preprocessor ] ) ) {
			// And no other preprocessor has run ...
			if ( empty( $args['preprocessed'] ) ) {
				$args['preprocessed'] = $args['css'];
				$args['css']          = call_user_func( $preprocessors[ $preprocessor ]['callback'], $args['css'] );
			} else {
				trigger_error( 'Jetpack CSS Preprocessor specified, but something else has already modified the argument.', E_USER_WARNING ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
			}
		}

		return $args;
	}

	/**
	 * When on the edit screen, make sure the custom content width
	 * setting is applied to the large image size.
	 *
	 * @param array  $dims    Array of image dimensions (width and height).
	 * @param string $size    Size of the resulting image.
	 * @param null   $context Context the image is being resized for. `edit` or `display`.
	 *
	 * @return array
	 */
	public static function editor_max_image_size( $dims, $size = 'medium', $context = null ) {
		list( $width, $height ) = $dims;

		if ( 'large' === $size && 'edit' === $context ) {
			$width = Jetpack::get_content_width();
		}

		return array( $width, $height );
	}

	/**
	 * Override the content_width with a custom value if one is set.
	 *
	 * @param int $content_width Content Width value to be updated.
	 *
	 * @return int
	 */
	public static function jetpack_content_width( $content_width ) {
		$custom_content_width = 0;

		$jetpack_custom_css = get_theme_mod( 'jetpack_custom_css', array() );
		if ( isset( $jetpack_custom_css['content_width'] ) ) {
			$custom_content_width = $jetpack_custom_css['content_width'];
		}

		if ( $custom_content_width > 0 ) {
			return $custom_content_width;
		}

		return $content_width;
	}

	/**
	 * Currently this filter function gets called on
	 * 'template_redirect' action and
	 * 'admin_init' action
	 */
	public static function set_content_width() {
		// Don't apply this filter on the Edit CSS page.
		if ( isset( $_GET['page'] ) && 'editcss' === $_GET['page'] && is_admin() ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nothing is changed on the site.
			return;
		}

		$GLOBALS['content_width'] = Jetpack::get_content_width();
	}

	/**
	 * Make sure the preprocessor we're saving is one we know about.
	 *
	 * @param string $preprocessor The preprocessor to sanitize.
	 *
	 * @return null|string
	 */
	public static function sanitize_preprocessor( $preprocessor ) {
		/** This filter is documented in modules/custom-css/custom-css.php */
		$preprocessors = apply_filters( 'jetpack_custom_css_preprocessors', array() );
		if ( empty( $preprocessor ) || array_key_exists( $preprocessor, $preprocessors ) ) {
			return $preprocessor;
		}
		return null;
	}

	/**
	 * Get the base10 intval.
	 *
	 * This is used as a setting's sanitize_callback; we can't use just plain
	 * intval because the second argument is not what intval() expects.
	 *
	 * @access public
	 *
	 * @param mixed $value Number to convert.
	 * @return int Integer.
	 */
	public static function intval_base10( $value ) {
		return (int) $value;
	}

	/**
	 * Add a footer action on revision.php to print some customizations for the theme switcher.
	 */
	public static function load_revision_php() {
		add_action( 'admin_footer', array( __CLASS__, 'revision_admin_footer' ) );
	}

	/**
	 * Print the theme switcher on revision.php and move it into place.
	 */
	public static function revision_admin_footer() {
		$post = get_post();
		if ( 'custom_css' !== $post->post_type ) {
			return;
		}
		$stylesheet = $post->post_title;
		?>
<script type="text/html" id="tmpl-other-themes-switcher">
		<?php self::revisions_switcher_box( $stylesheet ); ?>
</script>
<style>
.other-themes-wrap {
	float: right;
	background-color: #fff;
	-webkit-box-shadow: 0 1px 3px rgba(0,0,0,0.1);
	box-shadow: 0 1px 3px rgba(0,0,0,0.1);
	padding: 5px 10px;
	margin-bottom: 10px;
}
.other-themes-wrap label {
	display: block;
	margin-bottom: 10px;
}
.other-themes-wrap select {
	float: left;
	width: 77%;
}
.other-themes-wrap button {
	float: right;
	width: 20%;
}
.revisions {
	clear: both;
}
/* Hide the back-to-post link */
.long-header + a {
	display: none;
}
</style>
<script>
(function($){
	var switcher = $('#tmpl-other-themes-switcher').html(),
		qty = $( switcher ).find('select option').length,
		$switcher;

	if ( qty >= 3 ) {
		$('h1.long-header').before( switcher );
		$switcher = $('.other-themes-wrap');
		$switcher.find('button').on('click', function(e){
			e.preventDefault();
			if ( $switcher.find('select').val() ) {
				window.location.href = $switcher.find('select').val();
			}
		})
	}
})(jQuery);
</script>
		<?php
	}

	/**
	 * The HTML for the theme revision switcher box.
	 *
	 * @param string $stylesheet Stylesheet name.
	 */
	public static function revisions_switcher_box( $stylesheet = '' ) {
		$themes = self::get_all_themes_with_custom_css();
		?>
		<div class="other-themes-wrap">
			<label for="other-themes"><?php esc_html_e( 'Select another theme to view its custom CSS.', 'jetpack' ); ?></label>
			<select id="other-themes">
				<option value=""><?php esc_html_e( 'Select a theme&hellip;', 'jetpack' ); ?></option>
				<?php
				foreach ( $themes as $theme_stylesheet => $data ) {
					$revisions = wp_get_post_revisions( $data['post']->ID, array( 'posts_per_page' => 1 ) );
					if ( ! $revisions ) {
						?>
						<option value="<?php echo esc_url( add_query_arg( 'id', $data['post']->ID, menu_page_url( 'editcss', 0 ) ) ); ?>" <?php disabled( $stylesheet, $theme_stylesheet ); ?>>
							<?php echo esc_html( $data['label'] ); ?>
							<?php
								// translators: how long ago the stylesheet was modified.
								printf( esc_html__( '(modified %s ago)', 'jetpack' ), human_time_diff( strtotime( $data['post']->post_modified_gmt ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							?>
						</option>
						<?php
						continue;
					}
					$revision = array_shift( $revisions );
					?>
					<option value="<?php echo esc_url( get_edit_post_link( $revision->ID ) ); ?>" <?php disabled( $stylesheet, $theme_stylesheet ); ?>>
						<?php echo esc_html( $data['label'] ); ?>
						<?php
							// translators: how long ago the stylesheet was modified.
							printf( esc_html__( '(modified %s ago)', 'jetpack' ), human_time_diff( strtotime( $data['post']->post_modified_gmt ) ) );  // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
					</option>
					<?php
				}
				?>
			</select>
			<button class="button" id="other_theme_custom_css_switcher"><?php esc_html_e( 'Switch', 'jetpack' ); ?></button>
		</div>
		<?php
	}
}

Jetpack_Custom_CSS_Enhancements::add_hooks();

if ( ! function_exists( 'safecss_class' ) ) :
	/**
	 * Load in the class only when needed.  Makes lighter load by having one less class in memory.
	 */
	function safecss_class() {
		// Wrapped so we don't need the parent class just to load the plugin.
		if ( class_exists( 'safecss' ) ) {
			return;
		}

		require_once __DIR__ . '/csstidy/class.csstidy.php';

		/**
		 * Class safecss
		 */
		class safecss extends csstidy_optimise { // phpcs:ignore

			/**
			 * Optimises $css after parsing.
			 */
			public function postparse() { // phpcs:ignore MediaWiki.Usage.NestedFunctions.NestedFunction

				/** This action is documented in modules/custom-css/custom-css.php */
				do_action( 'csstidy_optimize_postparse', $this );

				return parent::postparse();
			}

			/**
			 * Optimises a sub-value.
			 */
			public function subvalue() { // phpcs:ignore MediaWiki.Usage.NestedFunctions.NestedFunction

				/** This action is documented in modules/custom-css/custom-css.php */
				do_action( 'csstidy_optimize_subvalue', $this );

				return parent::subvalue();
			}
		}
	}
endif;
