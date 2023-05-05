<?php
/**
 * Theme Tools: Author Bio functions.
 *
 * @package automattic/jetpack
 */

/**
 * The function to display Author Bio in a theme.
 */
function jetpack_author_bio() {
	// If the theme doesn't support 'jetpack-content-options', don't continue.
	if ( ! current_theme_supports( 'jetpack-content-options' ) ) {
		return;
	}

	$options            = get_theme_support( 'jetpack-content-options' );
	$author_bio         = ( ! empty( $options[0]['author-bio'] ) ) ? $options[0]['author-bio'] : null;
	$author_bio_default = ( isset( $options[0]['author-bio-default'] ) && false === $options[0]['author-bio-default'] ) ? '' : 1;

	// If the theme doesn't support 'jetpack-content-options[ 'author-bio' ]', don't continue.
	if ( true !== $author_bio ) {
		return;
	}

	// If 'jetpack_content_author_bio' is false, don't continue.
	if ( ! get_option( 'jetpack_content_author_bio', $author_bio_default ) ) {
		return;
	}

	// If we aren't on a single post, don't continue.
	if ( ! is_single() ) {
		return;
	}
	?>
	<div class="entry-author">
		<div class="author-avatar">
			<?php
			/**
			 * Filter the author bio avatar size.
			 *
			 * @param int $size The avatar height and width size in pixels.
			 *
			 * @module theme-tools
			 *
			 * @since 4.5.0
			 */
			$author_bio_avatar_size = apply_filters( 'jetpack_author_bio_avatar_size', 48 );

			echo get_avatar( get_the_author_meta( 'user_email' ), $author_bio_avatar_size );
			?>
		</div><!-- .author-avatar -->

		<div class="author-heading">
			<h2 class="author-title">
				<?php
					/* translators: %s: post author */
					printf( esc_html__( 'Published by %s', 'jetpack' ), '<span class="author-name">' . get_the_author() . '</span>' );
				?>
			</h2>
		</div><!-- .author-heading -->

		<p class="author-bio">
			<?php the_author_meta( 'description' ); ?>
			<a class="author-link" href="<?php echo esc_url( get_author_posts_url( get_the_author_meta( 'ID' ) ) ); ?>" rel="author">
				<?php
					/* translators: %s: post author */
					printf( esc_html__( 'View all posts by %s', 'jetpack' ), get_the_author() );
				?>
			</a>
		</p><!-- .author-bio -->
	</div><!-- .entry-auhtor -->
	<?php
}
