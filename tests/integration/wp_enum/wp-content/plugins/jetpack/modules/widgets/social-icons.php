<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Social Icons Widget.
 */
class Jetpack_Widget_Social_Icons extends WP_Widget {

	const ID_BASE = 'jetpack_widget_social_icons';

	/**
	 * Default widget options.
	 *
	 * @var array Default widget options.
	 */
	protected $defaults;

	/**
	 * Widget constructor.
	 */
	public function __construct() {
		global $pagenow;

		$widget_ops = array(
			'classname'                   => 'jetpack_widget_social_icons',
			'description'                 => __( 'Add social-media icons to your site.', 'jetpack' ),
			'show_instance_in_rest'       => true,
			'customize_selective_refresh' => true,
		);

		parent::__construct(
			'jetpack_widget_social_icons',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Social Icons', 'jetpack' ) ),
			$widget_ops
		);

		$this->defaults = array(
			'title'     => __( 'Follow Us', 'jetpack' ),
			'icon-size' => 'medium',
			'new-tab'   => false,
			'icons'     => array(
				array(
					'url' => '',
				),
			),
		);

		// Enqueue admin scrips and styles, only in the customizer or the old widgets page.
		if ( is_customize_preview() || 'widgets.php' === $pagenow ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );
			add_action( 'admin_print_footer_scripts', array( $this, 'render_admin_js' ) );
		}

		// Enqueue scripts and styles for the display of the widget, on the frontend or in the customizer.
		if ( is_active_widget( false, $this->id, $this->id_base, true ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_icon_scripts' ) );
			add_action( 'wp_footer', array( $this, 'include_svg_icons' ), 9999 );
		}

		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the "Social Icons" widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = self::ID_BASE;
		return $widget_types;
	}

	/**
	 * Script & styles for admin widget form.
	 */
	public function enqueue_admin_scripts() {
		wp_enqueue_script(
			'jetpack-widget-social-icons-script',
			plugins_url( 'social-icons/social-icons-admin.js', __FILE__ ),
			array( 'jquery', 'jquery-ui-sortable' ),
			'20170506',
			true
		);
		wp_enqueue_style(
			'jetpack-widget-social-icons-admin',
			plugins_url( 'social-icons/social-icons-admin.css', __FILE__ ),
			array(),
			'20170506'
		);
	}

	/**
	 * Styles for front-end widget.
	 */
	public function enqueue_icon_scripts() {
		wp_enqueue_style( 'jetpack-widget-social-icons-styles', plugins_url( 'social-icons/social-icons.css', __FILE__ ), array(), '20170506' );
	}

	/**
	 * JavaScript for admin widget form.
	 */
	public function render_admin_js() {
		?>
		<script type="text/html" id="tmpl-jetpack-widget-social-icons-template">
			<?php self::render_icons_template(); ?>
		</script>
		<?php
	}

	/**
	 * Add SVG definitions to the footer.
	 */
	public function include_svg_icons() {
		// Define SVG sprite file in Jetpack.
		$svg_icons = dirname( __DIR__ ) . '/theme-tools/social-menu/social-menu.svg';

		// Define SVG sprite file in WPCOM.
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$svg_icons = dirname( __DIR__ ) . '/social-menu/social-menu.svg';
		}

		// If it exists, include it.
		if ( is_file( $svg_icons ) ) {
			require_once $svg_icons;
		}
	}

	/**
	 * Front-end display of widget.
	 *
	 * @see WP_Widget::widget()
	 *
	 * @param array $args Widget arguments.
	 * @param array $instance Saved values from database.
	 */
	public function widget( $args, $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults );

		/** This filter is documented in wp-includes/widgets/class-wp-widget-pages.php */
		$title = apply_filters( 'widget_title', $instance['title'], $instance, $this->id_base );

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		if ( ! empty( $title ) ) {
			echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		if ( ! empty( $instance['icons'] ) ) :

			// Get supported social icons.
			$social_icons = $this->get_supported_icons();
			$default_icon = $this->get_svg_icon( array( 'icon' => 'chain' ) );

			?>

			<ul class="jetpack-social-widget-list size-<?php echo esc_attr( $instance['icon-size'] ); ?>">

				<?php foreach ( $instance['icons'] as $icon ) : ?>

					<?php if ( ! empty( $icon['url'] ) ) : ?>
						<li class="jetpack-social-widget-item">
							<?php
							printf(
								'<a href="%1$s" %2$s>',
								esc_url( $icon['url'], array( 'http', 'https', 'mailto', 'skype' ) ),
								true === $instance['new-tab'] ?
									'target="_blank" rel="noopener noreferrer"' :
									'target="_self"'
							);

							$found_icon = false;

							foreach ( $social_icons as $social_icon ) {
								foreach ( $social_icon['url'] as $url_fragment ) {
									/*
									 * url_fragment can be a URL host, or a regex, starting with #.
									 * Let's check for both scenarios.
									 */
									if (
										// First Regex.
										(
											'#' === substr( $url_fragment, 0, 1 ) && '#' === substr( $url_fragment, -1 )
											&& preg_match( $url_fragment, $icon['url'] )
										)
										// Then, regular host name.
										|| false !== strpos( $icon['url'], $url_fragment )
									) {
										printf(
											'<span class="screen-reader-text">%1$s</span>%2$s',
											esc_attr( $social_icon['label'] ),
											// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
											$this->get_svg_icon(
												array(
													'icon' => esc_attr( $social_icon['icon'] ),
												)
											)
										);
										$found_icon = true;
										break 2;
									}
								}
							}

							if ( ! $found_icon ) {
								echo $default_icon; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							}
							?>
							</a>
						</li>
					<?php endif; ?>

				<?php endforeach; ?>

			</ul>

			<?php
		endif;

		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'social_icons' );
	}

	/**
	 * Sanitize widget form values as they are saved.
	 *
	 * @see WP_Widget::update()
	 *
	 * @param array $new_instance Values just sent to be saved.
	 * @param array $old_instance Previously saved values from database.
	 *
	 * @return array Updated safe values to be saved.
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$instance = array();

		$instance['title']     = sanitize_text_field( $new_instance['title'] );
		$instance['icon-size'] = $this->defaults['icon-size'];
		$instance['url-icons'] = array_key_exists( 'url-icons', $new_instance ) ? $new_instance['url-icons'] : array();

		if ( in_array( $new_instance['icon-size'], array( 'small', 'medium', 'large' ), true ) ) {
			$instance['icon-size'] = $new_instance['icon-size'];
		}

		$instance['new-tab'] = isset( $new_instance['new-tab'] ) ? (bool) $new_instance['new-tab'] : false;
		$instance['icons']   = array();

		if ( array_key_exists( 'url-icons', $new_instance ) ) {
			foreach ( $new_instance['url-icons'] as $url ) {
				$url = filter_var( $url, FILTER_SANITIZE_URL );

				if ( ! empty( $url ) ) {
					$instance['icons'][] = array(
						'url' => $url,
					);
				}
			}
		}

		return $instance;
	}

	/**
	 * Back-end widget form.
	 *
	 * @see WP_Widget::form()
	 *
	 * @param array $instance Previously saved values from database.
	 *
	 * @return string|void
	 */
	public function form( $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults );
		$title    = sanitize_text_field( $instance['title'] );
		$sizes    = array(
			'small'  => __( 'Small', 'jetpack' ),
			'medium' => __( 'Medium', 'jetpack' ),
			'large'  => __( 'Large', 'jetpack' ),
		);
		$new_tab  = isset( $instance['new-tab'] ) ? (bool) $instance['new-tab'] : false;
		?>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title:', 'jetpack' ); ?></label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $title ); ?>" />
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'icon-size' ) ); ?>"><?php esc_html_e( 'Size:', 'jetpack' ); ?></label>
			<select class="widefat" name="<?php echo esc_attr( $this->get_field_name( 'icon-size' ) ); ?>">
				<?php foreach ( $sizes as $value => $label ) : ?>
					<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $value, $instance['icon-size'] ); ?>><?php echo esc_attr( $label ); ?></option>
				<?php endforeach; ?>
			</select>
		</p>

		<div class="jetpack-social-icons-widget-list"
			data-url-icon-id="<?php echo esc_attr( $this->get_field_id( 'url-icons' ) ); ?>"
			data-url-icon-name="<?php echo esc_attr( $this->get_field_name( 'url-icons' ) ); ?>"
		>

			<?php
			foreach ( $instance['icons'] as $icon ) {
				self::render_icons_template(
					array(
						'url-icon-id'   => $this->get_field_id( 'url-icons' ),
						'url-icon-name' => $this->get_field_name( 'url-icons' ),
						'url-value'     => $icon['url'],
					)
				);
			}
			?>

		</div>

		<p class="jetpack-social-icons-widget add-button">
			<button type="button" class="button jetpack-social-icons-add-button">
				<?php esc_html_e( 'Add an icon', 'jetpack' ); ?>
			</button>
		</p>

		<?php
		switch ( get_locale() ) {
			case 'es':
				$support = 'https://es.support.wordpress.com/social-media-icons-widget/#iconos-disponibles';
				break;

			case 'pt-br':
				$support = 'https://br.support.wordpress.com/widgets/widget-de-icones-sociais/#ícones-disponíveis';
				break;

			default:
				$support = 'https://en.support.wordpress.com/widgets/social-media-icons-widget/#available-icons';
		}
		?>

		<p>
			<em><a href="<?php echo esc_url( $support ); ?>" target="_blank" rel="noopener noreferrer">
				<?php esc_html_e( 'View available icons', 'jetpack' ); ?>
			</a></em>
		</p>

		<p>
			<input type="checkbox" class="checkbox" id="<?php echo esc_attr( $this->get_field_id( 'new-tab' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'new-tab' ) ); ?>" <?php checked( $new_tab ); ?> />
			<label for="<?php echo esc_attr( $this->get_field_id( 'new-tab' ) ); ?>"><?php esc_html_e( 'Open link in a new tab', 'jetpack' ); ?></label>
		</p>

		<?php
	}

	/**
	 * Generates template to add icons.
	 *
	 * @param array $args Template arguments.
	 */
	private static function render_icons_template( $args = array() ) {
		$defaults = array(
			'url-icon-id'   => '',
			'url-icon-name' => '',
			'url-value'     => '',
		);

		$args = wp_parse_args( $args, $defaults );
		?>

		<div class="jetpack-social-icons-widget-item">
			<div class="jetpack-social-icons-widget-item-wrapper">
				<div class="handle"></div>

				<p class="jetpack-widget-social-icons-url">
					<?php
						printf(
							'<input class="widefat" id="%1$s" name="%2$s[]" type="text" placeholder="%3$s" value="%4$s"/>',
							esc_attr( $args['url-icon-id'] ),
							esc_attr( $args['url-icon-name'] ),
							esc_attr__( 'Account URL', 'jetpack' ),
							esc_url( $args['url-value'], array( 'http', 'https', 'mailto', 'skype' ) )
						);
					?>
				</p>

				<p class="jetpack-widget-social-icons-remove-item">
					<a class="jetpack-widget-social-icons-remove-item-button" href="javascript:;">
						<?php esc_html_e( 'Remove', 'jetpack' ); ?>
					</a>
				</p>
			</div>
		</div>

		<?php
	}

	/**
	 * Return SVG markup.
	 *
	 * @param array $args {
	 *     Parameters needed to display an SVG.
	 *
	 *     @type string $icon  Required SVG icon filename.
	 * }
	 * @return string SVG markup.
	 */
	public function get_svg_icon( $args = array() ) {
		// Make sure $args are an array.
		if ( empty( $args ) ) {
			return esc_html__( 'Please define default parameters in the form of an array.', 'jetpack' );
		}

		// Set defaults.
		$defaults = array(
			'icon' => '',
		);

		// Parse args.
		$args = wp_parse_args( $args, $defaults );

		// Define an icon.
		if ( false === array_key_exists( 'icon', $args ) ) {
			return esc_html__( 'Please define an SVG icon filename.', 'jetpack' );
		}

		// Set aria hidden.
		$aria_hidden = ' aria-hidden="true"';

		// Begin SVG markup.
		$svg = '<svg class="icon icon-' . esc_attr( $args['icon'] ) . '"' . $aria_hidden . ' role="presentation">';

		/*
		 * Display the icon.
		 *
		 * The whitespace around `<use>` is intentional - it is a work around to a keyboard navigation bug in Safari 10.
		 *
		 * See https://core.trac.wordpress.org/ticket/38387.
		 */
		$svg .= ' <use href="#icon-' . esc_html( $args['icon'] ) . '" xlink:href="#icon-' . esc_html( $args['icon'] ) . '"></use> ';

		$svg .= '</svg>';

		return $svg;
	}

	/**
	 * Returns an array of supported social links (URL, icon, and label).
	 *
	 * @return array $social_links_icons
	 */
	public function get_supported_icons() {
		$social_links_icons = array(
			array(
				'url'   => array( '500px.com' ),
				'icon'  => '500px',
				'label' => '500px',
			),
			array(
				'url'   => array(
					'#https?:\/\/(www\.)?amazon\.(com|cn|in|fr|de|it|nl|es|co|ca)\/#',
				),
				'icon'  => 'amazon',
				'label' => 'Amazon',
			),
			array(
				'url'   => array( 'apple.com' ),
				'icon'  => 'apple',
				'label' => 'Apple',
			),
			array(
				'url'   => array( 'itunes.com' ),
				'icon'  => 'apple',
				'label' => 'iTunes',
			),
			array(
				'url'   => array( 'bandcamp.com' ),
				'icon'  => 'bandcamp',
				'label' => 'Bandcamp',
			),
			array(
				'url'   => array( 'behance.net' ),
				'icon'  => 'behance',
				'label' => 'Behance',
			),
			array(
				'url'   => array(
					'blogger.com',
					'blogspot.com',
				),
				'icon'  => 'blogger',
				'label' => 'Blogger',
			),
			array(
				'url'   => array( 'codepen.io' ),
				'icon'  => 'codepen',
				'label' => 'CodePen',
			),
			array(
				'url'   => array( 'deviantart.com' ),
				'icon'  => 'deviantart',
				'label' => 'DeviantArt',
			),
			array(
				'url'   => array( 'digg.com' ),
				'icon'  => 'digg',
				'label' => 'Digg',
			),
			array(
				'url'   => array( '#discord\.gg|discordapp\.com#' ),
				'icon'  => 'discord',
				'label' => 'Discord',
			),
			array(
				'url'   => array( 'dribbble.com' ),
				'icon'  => 'dribbble',
				'label' => 'Dribbble',
			),
			array(
				'url'   => array( 'dropbox.com' ),
				'icon'  => 'dropbox',
				'label' => 'Dropbox',
			),
			array(
				'url'   => array( 'etsy.com' ),
				'icon'  => 'etsy',
				'label' => 'Etsy',
			),
			array(
				'url'   => array( 'eventbrite.com' ),
				'icon'  => 'eventbrite',
				'label' => 'Eventbrite',
			),
			array(
				'url'   => array( 'facebook.com' ),
				'icon'  => 'facebook',
				'label' => 'Facebook',
			),
			array(
				'url'   => array( 'flickr.com' ),
				'icon'  => 'flickr',
				'label' => 'Flickr',
			),
			array(
				'url'   => array( 'foursquare.com' ),
				'icon'  => 'foursquare',
				'label' => 'Foursquare',
			),
			array(
				'url'   => array( 'ghost.org' ),
				'icon'  => 'ghost',
				'label' => 'Ghost',
			),
			array(
				'url'   => array( 'goodreads.com' ),
				'icon'  => 'goodreads',
				'label' => 'Goodreads',
			),
			array(
				'url'   => array( '#google\.(com|co\.uk|ca|cn|it)#' ),
				'icon'  => 'google',
				'label' => 'Google',
			),
			array(
				'url'   => array( 'github.com' ),
				'icon'  => 'github',
				'label' => 'GitHub',
			),
			array(
				'url'   => array( 'instagram.com' ),
				'icon'  => 'instagram',
				'label' => 'Instagram',
			),
			array(
				'url'   => array( 'linkedin.com' ),
				'icon'  => 'linkedin',
				'label' => 'LinkedIn',
			),
			array(
				'url'   => array( 'mailto:' ),
				'icon'  => 'mail',
				'label' => __( 'Email', 'jetpack' ),
			),
			array(
				'url'   => jetpack_mastodon_get_instance_list(),
				'icon'  => 'mastodon',
				'label' => 'Mastodon',
			),
			array(
				'url'   => array( 'meetup.com' ),
				'icon'  => 'meetup',
				'label' => 'Meetup',
			),
			array(
				'url'   => array( 'medium.com' ),
				'icon'  => 'medium',
				'label' => 'Medium',
			),
			array(
				'url'   => array( 'patreon.com' ),
				'icon'  => 'patreon',
				'label' => 'Patreon',
			),
			array(
				'url'   => array( 'pinterest.' ),
				'icon'  => 'pinterest',
				'label' => 'Pinterest',
			),
			array(
				'url'   => array( 'getpocket.com' ),
				'icon'  => 'pocket',
				'label' => 'Pocket',
			),
			array(
				'url'   => array( 'ravelry.com' ),
				'icon'  => 'ravelry',
				'label' => 'Ravelry',
			),
			array(
				'url'   => array( 'reddit.com' ),
				'icon'  => 'reddit',
				'label' => 'Reddit',
			),
			array(
				'url'   => array( 'skype.com' ),
				'icon'  => 'skype',
				'label' => 'Skype',
			),
			array(
				'url'   => array( 'skype:' ),
				'icon'  => 'skype',
				'label' => 'Skype',
			),
			array(
				'url'   => array( 'slideshare.net' ),
				'icon'  => 'slideshare',
				'label' => 'SlideShare',
			),
			array(
				'url'   => array( 'snapchat.com' ),
				'icon'  => 'snapchat',
				'label' => 'Snapchat',
			),
			array(
				'url'   => array( 'soundcloud.com' ),
				'icon'  => 'soundcloud',
				'label' => 'SoundCloud',
			),
			array(
				'url'   => array( 'spotify.com' ),
				'icon'  => 'spotify',
				'label' => 'Spotify',
			),
			array(
				'url'   => array( 'stackoverflow.com' ),
				'icon'  => 'stackoverflow',
				'label' => 'Stack Overflow',
			),
			array(
				'url'   => array( 'strava.com' ),
				'icon'  => 'strava',
				'label' => 'Strava',
			),
			array(
				'url'   => array( 'stumbleupon.com' ),
				'icon'  => 'stumbleupon',
				'label' => 'StumbleUpon',
			),
			array(
				'url'   => array( '#https?:\/\/(www\.)?(telegram|t)\.me#' ),
				'icon'  => 'telegram',
				'label' => 'Telegram',
			),
			array(
				'url'   => array( 'tiktok.com' ),
				'icon'  => 'tiktok',
				'label' => 'TikTok',
			),
			array(
				'url'   => array( 'tumblr.com' ),
				'icon'  => 'tumblr',
				'label' => 'Tumblr',
			),
			array(
				'url'   => array( 'twitch.tv' ),
				'icon'  => 'twitch',
				'label' => 'Twitch',
			),
			array(
				'url'   => array( 'twitter.com' ),
				'icon'  => 'twitter',
				'label' => 'Twitter',
			),
			array(
				'url'   => array( 'vimeo.com' ),
				'icon'  => 'vimeo',
				'label' => 'Vimeo',
			),
			array(
				'url'   => array( 'vk.com' ),
				'icon'  => 'vk',
				'label' => 'VK',
			),
			array(
				'url'   => array( 'whatsapp.com' ),
				'icon'  => 'whatsapp',
				'label' => 'WhatsApp',
			),
			array(
				'url'   => array( 'woocommerce.com' ),
				'icon'  => 'woocommerce',
				'label' => 'WooCommerce',
			),
			array(
				'url'   => array( '#wordpress\.(com|org)#' ),
				'icon'  => 'wordpress',
				'label' => 'WordPress',
			),
			array(
				'url'   => array( 'yelp.com' ),
				'icon'  => 'yelp',
				'label' => 'Yelp',
			),
			array(
				'url'   => array( 'xanga.com' ),
				'icon'  => 'xanga',
				'label' => 'Xanga',
			),
			array(
				'url'   => array( 'youtube.com' ),
				'icon'  => 'youtube',
				'label' => 'YouTube',
			),

			// keep feed at the end so that more specific icons can take precedence.
			array(
				'url'   => array(
					'/feed/',         // WordPress default feed url.
					'/feeds/',        // Blogspot and others.
					'/blog/feed',     // No trailing slash WordPress feed, could use /feed but may match unexpectedly.
					'format=RSS',     // Squarespace and others.
					'/rss',           // Tumblr.
					'/.rss',          // Reddit.
					'/rss.xml',       // Moveable Type, Typepad.
					'http://rss.',    // Old custom format.
					'https://rss.',   // Old custom format.
					'rss=1',
					'/feed=rss',      // Catches feed=rss / feed=rss2.
					'?feed=rss',      // WordPress non-permalink - Catches feed=rss / feed=rss2.
					'?feed=rdf',      // WordPress non-permalink.
					'?feed=atom',     // WordPress non-permalink.
					'http://feeds.',  // FeedBurner.
					'https://feeds.', // FeedBurner.
					'/feed.xml',      // Feedburner Alias, and others.
					'/index.xml',     // Moveable Type, and others.
					'/atom.xml',      // Typepad, Squarespace.
					'.atom',          // Shopify blog.
					'/atom',          // Some non-WordPress feeds.
					'index.rdf',      // Typepad.
				),
				'icon'  => 'feed',
				'label' => __( 'RSS Feed', 'jetpack' ),
			),
		);

		return $social_links_icons;
	}
} // Jetpack_Widget_Social_Icons

/**
 * Register and load the widget.
 *
 * @access public
 * @return void
 */
function jetpack_widget_social_icons_load() {
	register_widget( 'Jetpack_Widget_Social_Icons' );
}
add_action( 'widgets_init', 'jetpack_widget_social_icons_load' );
