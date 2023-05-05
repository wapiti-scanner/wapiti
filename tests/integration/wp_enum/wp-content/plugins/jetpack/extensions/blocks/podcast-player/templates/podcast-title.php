<?php
/**
 * Podcast Title template.
 *
 * @package automattic/jetpack
 */

// phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable -- This file expects $template_props set outside the file.

namespace Automattic\Jetpack\Extensions\Podcast_Player;

/**
 * Template variables.
 *
 * @var string $template_props
 */

if ( empty( $template_props['title'] ) ) {
	return;
}

?>
<span class="jetpack-podcast-player__podcast-title">
	<?php if ( ! empty( $template_props['link'] ) ) : ?>
		<a
			class="jetpack-podcast-player__link"
			href="<?php echo esc_url( $template_props['link'] ); ?>"
			target="_blank"
			rel="noopener noreferrer nofollow"
		>
			<?php echo esc_html( $template_props['title'] ); ?>
		</a>
		<?php
		else :
			echo esc_html( $template_props['title'] );
		endif;
		?>
</span>
