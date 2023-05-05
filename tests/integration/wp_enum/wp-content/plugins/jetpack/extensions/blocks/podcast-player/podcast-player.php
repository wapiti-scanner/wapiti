<?php
/**
 * Podcast Player Block.
 *
 * @since 8.4.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Podcast_Player;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;
use Jetpack_Podcast_Helper;

const FEATURE_NAME = 'podcast-player';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

if ( ! class_exists( 'Jetpack_Podcast_Helper' ) ) {
	require_once JETPACK__PLUGIN_DIR . '/_inc/lib/class-jetpack-podcast-helper.php';
}

/**
 * Registers the block for use in Gutenberg. This is done via an action so that
 * we can disable registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array(
			'attributes'      => array(
				'url'                    => array(
					'type' => 'string',
				),
				'itemsToShow'            => array(
					'type'    => 'integer',
					'default' => 5,
				),
				'showCoverArt'           => array(
					'type'    => 'boolean',
					'default' => true,
				),
				'showEpisodeTitle'       => array(
					'type'    => 'boolean',
					'default' => true,
				),
				'showEpisodeDescription' => array(
					'type'    => 'boolean',
					'default' => true,
				),
			),
			'render_callback' => __NAMESPACE__ . '\render_block',
			'supports'        => array(
				'align'   => array( 'wide', 'full' ),
				'spacing' => array(
					'padding' => true,
					'margin'  => true,
				),
			),
			// Since Gutenberg #31873.
			'style'           => 'wp-mediaelement',

		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Returns the error message wrapped in HTML if current user
 * has the capability to edit the post. Public visitors will
 * never see errors.
 *
 * @param string $message The error message to display.
 * @return string
 */
function render_error( $message ) {
	// Suppress errors for users unable to address them.
	if ( ! current_user_can( 'edit_posts' ) ) {
		return '';
	}
	return '<p>' . esc_html( $message ) . '</p>';
}

/**
 * Podcast Player block registration/dependency declaration.
 *
 * @param array  $attributes Array containing the Podcast Player block attributes.
 * @param string $content    Fallback content - a direct link to RSS, as rendered by save.js.
 * @return string
 */
function render_block( $attributes, $content ) {
	// Don't render an interactive version of the block outside the frontend context.
	if ( ! jetpack_is_frontend() ) {
		return $content;
	}

	// Test for empty URLS.
	if ( empty( $attributes['url'] ) ) {
		return render_error( __( 'No Podcast URL provided. Please enter a valid Podcast RSS feed URL.', 'jetpack' ) );
	}

	// Test for invalid URLs.
	if ( ! wp_http_validate_url( $attributes['url'] ) ) {
		return render_error( __( 'Your podcast URL is invalid and couldn\'t be embedded. Please double check your URL.', 'jetpack' ) );
	}

	if ( isset( $attributes['selectedEpisodes'] ) && count( $attributes['selectedEpisodes'] ) ) {
		$guids       = array_map(
			function ( $episode ) {
				return $episode['guid'];
			},
			$attributes['selectedEpisodes']
		);
		$player_args = array( 'guids' => $guids );
	} else {
		$player_args = array();
	}

	// Sanitize the URL.
	$attributes['url'] = esc_url_raw( $attributes['url'] );
	$player_data       = ( new Jetpack_Podcast_Helper( $attributes['url'] ) )->get_player_data( $player_args );

	if ( is_wp_error( $player_data ) ) {
		return render_error( $player_data->get_error_message() );
	}

	return render_player( $player_data, $attributes );
}

/**
 * Renders the HTML for the Podcast player and tracklist.
 *
 * @param array $player_data The player data details.
 * @param array $attributes Array containing the Podcast Player block attributes.
 * @return string The HTML for the podcast player.
 */
function render_player( $player_data, $attributes ) {
	// If there are no tracks (it is possible) then display appropriate user facing error message.
	if ( empty( $player_data['tracks'] ) ) {
		return render_error( __( 'No tracks available to play.', 'jetpack' ) );
	}

	// Only use the amount of tracks requested.
	$player_data['tracks'] = array_slice(
		$player_data['tracks'],
		0,
		absint( $attributes['itemsToShow'] )
	);

	// Generate a unique id for the block instance.
	$instance_id             = wp_unique_id( 'jetpack-podcast-player-block-' . get_the_ID() . '-' );
	$player_data['playerId'] = $instance_id;

	// Generate object to be used as props for PodcastPlayer.
	$player_props = array_merge(
		// Add all attributes.
		array( 'attributes' => $attributes ),
		// Add all player data.
		$player_data
	);

	$primary_colors    = get_colors( 'primary', $attributes, 'color' );
	$secondary_colors  = get_colors( 'secondary', $attributes, 'color' );
	$background_colors = get_colors( 'background', $attributes, 'background-color' );

	$player_classes_name  = trim( "{$secondary_colors['class']} {$background_colors['class']}" );
	$player_inline_style  = trim( "{$secondary_colors['style']} {$background_colors['style']}" );
	$player_inline_style .= get_css_vars( $attributes );
	$wrapper_attributes   = \WP_Block_Supports::get_instance()->apply_block_supports();
	$block_classname      = Blocks::classes( FEATURE_NAME, $attributes, array( 'is-default' ) );
	$is_amp               = Blocks::is_amp_request();

	ob_start();
	?>
	<div class="<?php echo esc_attr( $block_classname ); ?>"<?php echo ! empty( $wrapper_attributes['style'] ) ? ' style="' . esc_attr( $wrapper_attributes['style'] ) . '"' : ''; ?> id="<?php echo esc_attr( $instance_id ); ?>">
		<section
			class="jetpack-podcast-player <?php echo esc_attr( $player_classes_name ); ?>"
			style="<?php echo esc_attr( $player_inline_style ); ?>"
		>
			<?php
			render(
				'podcast-header',
				array_merge(
					$player_props,
					array(
						'primary_colors' => $primary_colors,
						'player_id'      => $player_data['playerId'],
					)
				)
			);
			?>
			<?php if ( count( $player_data['tracks'] ) > 1 ) : ?>
			<ol class="jetpack-podcast-player__tracks">
				<?php foreach ( $player_data['tracks'] as $track_index => $attachment ) : ?>
					<?php
					render(
						'playlist-track',
						array(
							'is_active'        => 0 === $track_index,
							'attachment'       => $attachment,
							'primary_colors'   => $primary_colors,
							'secondary_colors' => $secondary_colors,
						)
					);
					?>
				<?php endforeach; ?>
			</ol>
			<?php endif; ?>
		</section>
		<?php if ( ! $is_amp ) : ?>
		<script type="application/json"><?php echo wp_json_encode( $player_props ); ?></script>
		<?php endif; ?>
	</div>
	<?php
	/**
	 * Enqueue necessary scripts and styles.
	 */
	if ( ! $is_amp ) {
		wp_enqueue_style( 'wp-mediaelement' );
	}
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME, array( 'mediaelement' ) );

	return ob_get_clean();
}

/**
 * Given the color name, block attributes and the CSS property,
 * the function will return an array with the `class` and `style`
 * HTML attributes to be used straight in the markup.
 *
 * @example
 * $color = get_colors( 'secondary', $attributes, 'border-color'
 *  => array( 'class' => 'has-secondary', 'style' => 'border-color: #333' )
 *
 * @param string $name     Color attribute name, for instance `primary`, `secondary`, ...
 * @param array  $attrs    Block attributes.
 * @param string $property Color CSS property, fo instance `color`, `background-color`, ...
 * @return array           Colors array.
 */
function get_colors( $name, $attrs, $property ) {
	$attr_color  = "{$name}Color";
	$attr_custom = 'custom' . ucfirst( $attr_color );

	$color        = isset( $attrs[ $attr_color ] ) ? $attrs[ $attr_color ] : null;
	$custom_color = isset( $attrs[ $attr_custom ] ) ? $attrs[ $attr_custom ] : null;

	$colors = array(
		'class' => '',
		'style' => '',
	);

	if ( $color || $custom_color ) {
		$colors['class'] .= "has-{$name}";

		if ( $color ) {
			$colors['class'] .= " has-{$color}-{$property}";
		} elseif ( $custom_color ) {
			$colors['style'] .= "{$property}: {$custom_color};";
		}
	}

	return $colors;
}

/**
 * It generates a string with CSS variables according to the
 * block colors, prefixing each one with `--jetpack-podcast-player'.
 *
 * @param array $attrs Podcast Block attributes object.
 * @return string      CSS variables depending on block colors.
 */
function get_css_vars( $attrs ) {
	$colors_name = array( 'primary', 'secondary', 'background' );

	$inline_style = '';
	foreach ( $colors_name as $color ) {
		$hex_color = 'hex' . ucfirst( $color ) . 'Color';
		if ( ! empty( $attrs[ $hex_color ] ) ) {
			$inline_style .= " --jetpack-podcast-player-{$color}: {$attrs[ $hex_color ]};";
		}
	}
	return $inline_style;
}

/**
 * Render the given template in server-side.
 * Important note:
 *    The $template_props array will be extracted.
 *    This means it will create a var for each array item.
 *    Keep it mind when using this param to pass
 *    properties to the template.
 *
 * @param string $name           Template name, available in `./templates` folder.
 * @param array  $template_props Template properties. Optional.
 * @param bool   $print          Render template. True as default.
 * @return false|string          HTML markup or false.
 */
function render( $name, $template_props = array(), $print = true ) {
	if ( ! strpos( $name, '.php' ) ) {
		$name = $name . '.php';
	}

	$template_path = __DIR__ . '/templates/' . $name;

	if ( ! file_exists( $template_path ) ) {
		return '';
	}

	if ( $print ) {
		include $template_path;
	} else {
		ob_start();
		include $template_path;
		$markup = ob_get_contents();
		ob_end_clean();

		return $markup;
	}
}
