<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Assets;

/**
 * Embed recipe 'cards' in post, with basic styling and print functionality
 *
 * To Do
 * - defaults settings
 * - basic styles/themecolor styles
 * - validation/sanitization
 * - print styles
 *
 * @package automattic/jetpack
 */

/**
 * Register and display Recipes in posts.
 */
class Jetpack_Recipes {

	/**
	 * Have scripts and styles been enqueued already.
	 *
	 * @var bool
	 */
	private $scripts_and_style_included = false;

	/**
	 * Constructor
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'action_init' ) );
	}

	/**
	 * Returns KSES tags with Schema-specific attributes.
	 *
	 * @since 8.0.0
	 *
	 * @return array Array to be used by KSES.
	 */
	private static function kses_tags() {
		$allowedtags = wp_kses_allowed_html( 'post' );
		// Create an array of all the tags we'd like to add the itemprop attribute to.
		$tags = array( 'li', 'ol', 'ul', 'img', 'p', 'h3', 'time', 'span' );
		foreach ( $tags as $tag ) {
			if ( ! isset( $allowedtags[ $tag ] ) ) {
				$allowedtags[ $tag ] = array();
			}
			$allowedtags[ $tag ]['class']    = array();
			$allowedtags[ $tag ]['itemprop'] = array();
			$allowedtags[ $tag ]['datetime'] = array();
		}

		// Allow the handler <a on=""> in AMP.
		$allowedtags['a']['on'] = array();

		// Allow itemscope and itemtype for divs.
		if ( ! isset( $allowedtags['div'] ) ) {
			$allowedtags['div'] = array();
		}
		$allowedtags['div']['class']     = array();
		$allowedtags['div']['itemscope'] = array();
		$allowedtags['div']['itemtype']  = array();
		return $allowedtags;
	}

	/**
	 * Register our shortcode and enqueue necessary files.
	 */
	public function action_init() {
		// Enqueue styles if [recipe] exists.
		add_action( 'wp_head', array( $this, 'add_scripts' ), 1 );

		// Render [recipe], along with other shortcodes that can be nested within.
		add_shortcode( 'recipe', array( $this, 'recipe_shortcode' ) );
		add_shortcode( 'recipe-notes', array( $this, 'recipe_notes_shortcode' ) );
		add_shortcode( 'recipe-ingredients', array( $this, 'recipe_ingredients_shortcode' ) );
		add_shortcode( 'recipe-directions', array( $this, 'recipe_directions_shortcode' ) );
		add_shortcode( 'recipe-nutrition', array( $this, 'recipe_nutrition_shortcode' ) );
		add_shortcode( 'recipe-image', array( $this, 'recipe_image_shortcode' ) );
	}

	/**
	 * Enqueue scripts and styles
	 */
	public function add_scripts() {
		if ( empty( $GLOBALS['posts'] ) || ! is_array( $GLOBALS['posts'] ) ) {
			return;
		}

		foreach ( $GLOBALS['posts'] as $p ) {
			if ( isset( $p->post_content ) && has_shortcode( $p->post_content, 'recipe' ) ) {
				$this->scripts_and_style_included = true;
				break;
			}
		}

		if ( ! $this->scripts_and_style_included ) {
			return;
		}

		wp_enqueue_style( 'jetpack-recipes-style', plugins_url( '/css/recipes.css', __FILE__ ), array(), '20130919' );
		wp_style_add_data( 'jetpack-recipes-style', 'rtl', 'replace' );

		// add $themecolors-defined styles.
		wp_add_inline_style( 'jetpack-recipes-style', self::themecolor_styles() );

		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		wp_enqueue_script(
			'jetpack-recipes-printthis',
			Assets::get_file_url_for_environment( '_inc/build/shortcodes/js/recipes-printthis.min.js', 'modules/shortcodes/js/recipes-printthis.js' ),
			array( 'jquery' ),
			'20170202',
			false
		);

		wp_enqueue_script(
			'jetpack-recipes-js',
			Assets::get_file_url_for_environment( '_inc/build/shortcodes/js/recipes.min.js', 'modules/shortcodes/js/recipes.js' ),
			array( 'jquery', 'jetpack-recipes-printthis' ),
			'20131230',
			false
		);

		$title_var     = wp_title( '|', false, 'right' );
		$rtl           = is_rtl() ? '-rtl' : '';
		$print_css_var = plugins_url( "/css/recipes-print{$rtl}.css", __FILE__ );

		wp_localize_script(
			'jetpack-recipes-js',
			'jetpack_recipes_vars',
			array(
				'pageTitle' => $title_var,
				'loadCSS'   => $print_css_var,
			)
		);
	}

	/**
	 * Our [recipe] shortcode.
	 * Prints recipe data styled to look good on *any* theme.
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML for recipe shortcode.
	 */
	public static function recipe_shortcode( $atts, $content = '' ) {
		$atts = shortcode_atts(
			array(
				'title'       => '', // string.
				'servings'    => '', // intval.
				'time'        => '', // strtotime-compatible time description.
				'difficulty'  => '', // string.
				'print'       => '', // URL for external print version.
				'source'      => '', // string.
				'sourceurl'   => '', // URL string. Only used if source set.
				'image'       => '', // URL or attachment ID.
				'description' => '', // string.
				'cooktime'    => '', // strtotime-compatible time description.
				'preptime'    => '', // strtotime-compatible time description.
				'rating'      => '', // string.
			),
			$atts,
			'recipe'
		);

		return self::recipe_shortcode_html( $atts, $content );
	}

	/**
	 * The recipe output
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML output
	 */
	private static function recipe_shortcode_html( $atts, $content = '' ) {

		$html = '<div class="hrecipe h-recipe jetpack-recipe" itemscope itemtype="https://schema.org/Recipe">';

		// Print the recipe title if exists.
		if ( '' !== $atts['title'] ) {
			$html .= '<h3 class="p-name jetpack-recipe-title fn" itemprop="name">' . esc_html( $atts['title'] ) . '</h3>';
		}

		// Print the recipe meta if exists.
		if (
			'' !== $atts['servings']
			|| '' !== $atts['time']
			|| '' !== $atts['difficulty']
			|| '' !== $atts['print']
			|| '' !== $atts['preptime']
			|| '' !== $atts['cooktime']
			|| '' !== $atts['rating']
		) {
			$html .= '<ul class="jetpack-recipe-meta">';

			if ( '' !== $atts['servings'] ) {
				$html .= sprintf(
					'<li class="jetpack-recipe-servings p-yield yield" itemprop="recipeYield"><strong>%1$s: </strong>%2$s</li>',
					esc_html_x( 'Servings', 'recipe', 'jetpack' ),
					esc_html( $atts['servings'] )
				);
			}

			$time_types = array( 'preptime', 'cooktime', 'time' );
			foreach ( $time_types as $time_type ) {
				if ( '' === $atts[ $time_type ] ) {
					continue;
				}
				$html .= self::output_time( $atts[ $time_type ], $time_type );
			}

			if ( '' !== $atts['difficulty'] ) {
				$html .= sprintf(
					'<li class="jetpack-recipe-difficulty"><strong>%1$s: </strong>%2$s</li>',
					esc_html_x( 'Difficulty', 'recipe', 'jetpack' ),
					esc_html( $atts['difficulty'] )
				);
			}

			if ( '' !== $atts['rating'] ) {
				$html .= sprintf(
					'<li class="jetpack-recipe-rating">
						<strong>%1$s: </strong>
						<span itemprop="contentRating">%2$s</span>
					</li>',
					esc_html_x( 'Rating', 'recipe', 'jetpack' ),
					esc_html( $atts['rating'] )
				);
			}

			if ( '' !== $atts['source'] ) {
				$html .= sprintf(
					'<li class="jetpack-recipe-source"><strong>%1$s: </strong>',
					esc_html_x( 'Source', 'recipe', 'jetpack' )
				);

				if ( '' !== $atts['sourceurl'] ) :
					// Show the link if we have one.
					$html .= sprintf(
						'<a href="%2$s">%1$s</a>',
						esc_html( $atts['source'] ),
						esc_url( $atts['sourceurl'] )
					);
				else :
					// Skip the link.
					$html .= sprintf(
						'%1$s',
						esc_html( $atts['source'] )
					);
				endif;

				$html .= '</li>';
			}

			if ( 'false' !== $atts['print'] ) {
				$is_amp       = class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request();
				$print_action = $is_amp ? 'on="tap:AMP.print"' : '';
				$print_text   = $is_amp ? esc_html__( 'Print page', 'jetpack' ) : esc_html_x( 'Print', 'recipe', 'jetpack' );
				$html        .= sprintf(
					'<li class="jetpack-recipe-print"><a href="#" %1$s>%2$s</a></li>',
					$print_action,
					$print_text
				);
			}

			$html .= '</ul>';
		}

		// Output the image if we have one and it's not shown elsewhere.
		if ( '' !== $atts['image'] ) {
			if ( ! has_shortcode( $content, 'recipe-image' ) ) {
				$html .= self::output_image_html( $atts['image'] );
			}
		}

		// Output the description, if we have one.
		if ( '' !== $atts['description'] ) {
			$html .= sprintf(
				'<p class="jetpack-recipe-description" itemprop="description">%1$s</p>',
				esc_html( $atts['description'] )
			);
		}

		// Print content between codes.
		$html .= '<div class="jetpack-recipe-content">' . do_shortcode( $content ) . '</div>';

		// Close it up.
		$html .= '</div>';

		// If there is a recipe within a recipe, remove the shortcode.
		if ( has_shortcode( $html, 'recipe' ) ) {
			remove_shortcode( 'recipe' );
		}

		// Sanitize html.
		$html = wp_kses( $html, self::kses_tags() );

		// Return the HTML block.
		return $html;
	}

	/**
	 * Our [recipe-image] shortcode.
	 * Controls placement of image in recipe.
	 *
	 * @param array $atts Array of shortcode attributes.
	 *
	 * @return string HTML for recipe notes shortcode.
	 */
	public static function recipe_image_shortcode( $atts ) {
		$atts = shortcode_atts(
			array(
				'image' => '', // string.
				0       => '', // string.
			),
			$atts,
			'recipe-image'
		);
		$src  = $atts['image'];
		if ( ! empty( $atts[0] ) ) {
			$src = $atts[0];
		}
		return self::output_image_html( $src );
	}

	/**
	 * Our [recipe-notes] shortcode.
	 * Outputs ingredients, styled in a div.
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML for recipe notes shortcode.
	 */
	public static function recipe_notes_shortcode( $atts, $content = '' ) {
		$atts = shortcode_atts(
			array(
				'title' => '', // string.
			),
			$atts,
			'recipe-notes'
		);

		$html = '';

		// Print a title if one exists.
		if ( '' !== $atts['title'] ) {
			$html .= '<h4 class="jetpack-recipe-notes-title">' . esc_html( $atts['title'] ) . '</h4>';
		}

		$html .= '<div class="jetpack-recipe-notes">';

		// Format content using list functionality, if desired.
		$html .= self::output_list_content( $content, 'notes' );

		$html .= '</div>';

		// Sanitize html.
		$html = wp_kses( $html, self::kses_tags() );

		// Return the HTML block.
		return $html;
	}

	/**
	 * Our [recipe-ingredients] shortcode.
	 * Outputs notes, styled in a div.
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML for recipe ingredients shortcode.
	 */
	public static function recipe_ingredients_shortcode( $atts, $content = '' ) {
		$atts = shortcode_atts(
			array(
				'title' => esc_html_x( 'Ingredients', 'recipe', 'jetpack' ), // string.
			),
			$atts,
			'recipe-ingredients'
		);

		$html = '<div class="jetpack-recipe-ingredients">';

		// Print a title unless the user has opted to exclude it.
		if ( 'false' !== $atts['title'] ) {
			$html .= '<h4 class="jetpack-recipe-ingredients-title">' . esc_html( $atts['title'] ) . '</h4>';
		}

		// Format content using list functionality.
		$html .= self::output_list_content( $content, 'ingredients' );

		$html .= '</div>';

		// Sanitize html.
		$html = wp_kses( $html, self::kses_tags() );

		// Return the HTML block.
		return $html;
	}

	/**
	 * Our [recipe-nutrition] shortcode.
	 * Outputs notes, styled in a div.
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML for recipe nutrition shortcode.
	 */
	public static function recipe_nutrition_shortcode( $atts, $content = '' ) {
		$atts = shortcode_atts(
			array(
				'title' => esc_html_x( 'Nutrition', 'recipe', 'jetpack' ), // string.
			),
			$atts,
			'recipe-nutrition'
		);

		$html = '<div class="jetpack-recipe-nutrition p-nutrition nutrition">';

		// Print a title unless the user has opted to exclude it.
		if ( 'false' !== $atts['title'] ) {
			$html .= '<h4 class="jetpack-recipe-nutrition-title">' . esc_html( $atts['title'] ) . '</h4>';
		}

		// Format content using list functionality.
		$html .= self::output_list_content( $content, 'nutrition' );

		$html .= '</div>';

		// Sanitize html.
		$html = wp_kses( $html, self::kses_tags() );

		// Return the HTML block.
		return $html;
	}

	/**
	 * Reusable function to check for shortened formatting.
	 * Basically, users can create lists with the following shorthand:
	 * - item one
	 * - item two
	 * - item three
	 * And we'll magically convert it to a list. This has the added benefit
	 * of including itemprops for the recipe schema.
	 *
	 * @param string $content HTML content.
	 * @param string $type    Type of list.
	 *
	 * @return string content formatted as a list item
	 */
	private static function output_list_content( $content, $type ) {
		$html = '';

		switch ( $type ) {
			case 'directions':
				$list_item_replacement = '<li class="jetpack-recipe-directions">${1}</li>';
				$itemprop              = ' itemprop="recipeInstructions"';
				$listtype              = 'ol';
				break;
			case 'ingredients':
				$list_item_replacement = '<li class="jetpack-recipe-ingredient p-ingredient ingredient" itemprop="recipeIngredient">${1}</li>';
				$itemprop              = '';
				$listtype              = 'ul';
				break;
			case 'nutrition':
				$list_item_replacement = '<li class="jetpack-recipe-nutrition">${1}</li>';
				$itemprop              = ' itemprop="nutrition"';
				$listtype              = 'ul';
				break;
			case 'nutrition':
				$list_item_replacement = '<li class="jetpack-recipe-nutrition nutrition">${1}</li>';
				$itemprop              = ' itemprop="nutrition"';
				$listtype              = 'ul';
				break;
			default:
				$list_item_replacement = '<li class="jetpack-recipe-notes">${1}</li>';
				$itemprop              = '';
				$listtype              = 'ul';
		}

		// Check to see if the user is trying to use shortened formatting.
		if (
			strpos( $content, '&#8211;' ) !== false ||
			strpos( $content, '&#8212;' ) !== false ||
			strpos( $content, '-' ) !== false ||
			strpos( $content, '*' ) !== false ||
			strpos( $content, '#' ) !== false ||
			strpos( $content, '–' ) !== false || // ndash.
			strpos( $content, '—' ) !== false || // mdash.
			preg_match( '/\d+\.\s/', $content )
		) {
			// Remove breaks and extra whitespace.
			$content = str_replace( "<br />\n", "\n", $content );
			$content = trim( $content );

			$ul_pattern = '/(?:^|\n|\<p\>)+(?:[\-–—]+|\&#8211;|\&#8212;|\*)+\h+(.*)/mi';
			$ol_pattern = '/(?:^|\n|\<p\>)+(?:\d+\.|#+)+\h+(.*)/mi';

			preg_match_all( $ul_pattern, $content, $ul_matches );
			preg_match_all( $ol_pattern, $content, $ol_matches );

			if ( 0 !== count( $ul_matches[0] ) || 0 !== count( $ol_matches[0] ) ) {

				if ( 0 !== count( $ol_matches[0] ) ) {
					$listtype          = 'ol';
					$list_item_pattern = $ol_pattern;
				} else {
					$listtype          = 'ul';
					$list_item_pattern = $ul_pattern;
				}
				$html .= '<' . $listtype . $itemprop . '>';
				$html .= preg_replace( $list_item_pattern, $list_item_replacement, $content );
				$html .= '</' . $listtype . '>';

				// Strip out any empty <p> tags and stray </p> tags, because those are just silly.
				$empty_p_pattern = '/(<p>)*\s*<\/p>/mi';
				$html            = preg_replace( $empty_p_pattern, '', $html );
			} else {
				$html .= do_shortcode( $content );
			}
		} else {
			$html .= do_shortcode( $content );
		}

		// Return our formatted content.
		return $html;
	}

	/**
	 * Our [recipe-directions] shortcode.
	 * Outputs directions, styled in a div.
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML for recipe directions shortcode.
	 */
	public static function recipe_directions_shortcode( $atts, $content = '' ) {
		$atts = shortcode_atts(
			array(
				'title' => esc_html_x( 'Directions', 'recipe', 'jetpack' ), // string.
			),
			$atts,
			'recipe-directions'
		);

		$html = '<div class="jetpack-recipe-directions e-instructions">';

		// Print a title unless the user has specified to exclude it.
		if ( 'false' !== $atts['title'] ) {
			$html .= '<h4 class="jetpack-recipe-directions-title">' . esc_html( $atts['title'] ) . '</h4>';
		}

		// Format content using list functionality.
		$html .= self::output_list_content( $content, 'directions' );

		$html .= '</div>';

		// Sanitize html.
		$html = wp_kses( $html, self::kses_tags() );

		// Return the HTML block.
		return $html;
	}

	/**
	 * Outputs time meta tag.
	 *
	 * @param string $time_str  Raw time to output.
	 * @param string $time_type Type of time to show.
	 *
	 * @return string HTML for recipe time meta.
	 */
	private static function output_time( $time_str, $time_type ) {
		// Get a time that's supported by Schema.org.
		$duration = WPCOM_JSON_API_Date::format_duration( $time_str );
		// If no duration can be calculated, let's output what the user provided.
		if ( ! $duration ) {
			$duration = $time_str;
		}

		switch ( $time_type ) {
			case 'cooktime':
				$title    = _x( 'Cook Time', 'recipe', 'jetpack' );
				$itemprop = 'cookTime';
				break;
			case 'preptime':
				$title    = _x( 'Prep Time', 'recipe', 'jetpack' );
				$itemprop = 'prepTime';
				break;
			default:
				$title    = _x( 'Time', 'recipe', 'jetpack' );
				$itemprop = 'totalTime';
				break;
		}

		return sprintf(
			'<li class="jetpack-recipe-%3$s">
				<time itemprop="%4$s" datetime="%5$s"><strong>%1$s:</strong> <span class="%3$s">%2$s</span></time>
			</li>',
			esc_html( $title ),
			esc_html( $time_str ),
			esc_attr( $time_type ),
			esc_attr( $itemprop ),
			esc_attr( $duration )
		);
	}

	/**
	 * Outputs image tag for recipe.
	 *
	 * @param string $src The image source.
	 *
	 * @return string
	 */
	private static function output_image_html( $src ) {
		// Exit if there is no provided source.
		if ( ! $src ) {
			return '';
		}

		$image_attrs = array(
			'class'    => 'jetpack-recipe-image u-photo photo',
			'itemprop' => 'image',
		);

		if (
			function_exists( 'wp_lazy_loading_enabled' )
			&& wp_lazy_loading_enabled( 'img', 'wp_get_attachment_image' )
		) {
			$image_attrs['loading'] = 'lazy';
		}

		// If it's numeric, this may be an attachment.
		if ( is_numeric( $src ) ) {
			return wp_get_attachment_image(
				$src,
				'full',
				false,
				$image_attrs
			);
		}

		// Check if it's an absolute or relative URL, and return if not.
		if (
			0 !== strpos( $src, '/' )
			&& false === filter_var( $src, FILTER_VALIDATE_URL )
		) {
			return '';
		}

		$image_attrs_markup = '';
		foreach ( $image_attrs as $name => $value ) {
			$image_attrs_markup .= sprintf(
				' %1$s="%2$s"',
				esc_attr( $name ),
				esc_attr( $value )
			);
		}

		return sprintf(
			'<img%1$s src="%2$s" />',
			$image_attrs_markup,
			esc_url( $src )
		);
	}

	/**
	 * Use $themecolors array to style the Recipes shortcode
	 *
	 * @print style block
	 * @return string $style
	 */
	public function themecolor_styles() {
		global $themecolors;
		$style = '';

		if ( isset( $themecolors ) ) {
			$style .= '.jetpack-recipe { border-color: #' . esc_attr( $themecolors['border'] ) . '; }';
			$style .= '.jetpack-recipe-title { border-bottom-color: #' . esc_attr( $themecolors['link'] ) . '; }';
		}

		return $style;
	}

}

new Jetpack_Recipes();
