<?php
/**
 * Podcast Header Title template.
 *
 * @package automattic/jetpack
 */

//phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable -- This file expects $template_props set outside the file.

namespace Automattic\Jetpack\Extensions\Podcast_Player;

/**
 * Template variables.
 *
 * @var string $template_props
 */

if ( ! isset( $template_props['title'] ) && empty( $template_props['track']['title'] ) ) {
	return;
}

$track_link = empty( $template_props['track']['link'] ) ? $template_props['track']['src'] : $template_props['track']['link'];
?>

<h2 id="<?php echo esc_attr( $template_props['player_id'] ); ?>__title" class="jetpack-podcast-player__title">
	<span
		class="jetpack-podcast-player__current-track-title <?php echo esc_attr( $template_props['primary_colors']['class'] ); ?>"
		<?php echo isset( $template_props['primary_colors']['style'] ) ? 'style="' . esc_attr( $template_props['primary_colors']['style'] ) . '"' : ''; ?>
	>
		<?php
		echo esc_html( $template_props['track']['title'] );
		if ( ! empty( $track_link ) ) :
			// Prevent whitespace between title and link to cause a jump when JS kicks in.
			// phpcs:disable Squiz.PHP.EmbeddedPhp.ContentAfterEnd
			?><a
				class="jetpack-podcast-player__track-title-link"
				href="<?php echo esc_url( $track_link ); ?>"
				target="_blank"
				rel="noopener noreferrer nofollow"
			>
				<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
					<path d="M15.6 7.2H14v1.5h1.6c2 0 3.7 1.7 3.7 3.7s-1.7 3.7-3.7 3.7H14v1.5h1.6c2.8 0 5.2-2.3 5.2-5.2 0-2.9-2.3-5.2-5.2-5.2zM4.7 12.4c0-2 1.7-3.7 3.7-3.7H10V7.2H8.4c-2.9 0-5.2 2.3-5.2 5.2 0 2.9 2.3 5.2 5.2 5.2H10v-1.5H8.4c-2 0-3.7-1.7-3.7-3.7zm4.6.9h5.3v-1.5H9.3v1.5z" />
				</svg>
			</a>
		<?php endif; // phpcs:enable ?>
	</span>

	<?php
	// phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable -- This file expects $template_props set outside the file.

	if ( ! empty( $template_props['title'] ) ) :
		?>
		<span class="jetpack-podcast-player--visually-hidden"> - </span>

		<?php
		render(
			'podcast-title',
			array(
				'title' => $template_props['title'],
				'link'  => $template_props['link'],
			)
		);
		?>
	<?php endif; ?>
</h2>
