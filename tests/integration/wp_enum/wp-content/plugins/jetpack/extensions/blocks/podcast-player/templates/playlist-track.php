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
 * @var array $template_props
 */

$track_title    = $template_props['attachment']['title'];
$track_link     = empty( $template_props['attachment']['link'] ) ? $template_props['attachment']['src'] : $template_props['attachment']['link'];
$track_duration = ! empty( $template_props['attachment']['duration'] ) ? $template_props['attachment']['duration'] : '';

$class = 'jetpack-podcast-player__track ' . $template_props['secondary_colors']['class'];
$style = $template_props['secondary_colors']['style'];
if ( $template_props['is_active'] ) {
	$class = 'jetpack-podcast-player__track is-active ' . $template_props['primary_colors']['class'];
	$style = $template_props['primary_colors']['style'];
}

?>

<li
	class="<?php echo esc_attr( trim( $class ) ); ?>"
	style="<?php echo esc_attr( $style ); ?>"
>
	<a
		class="jetpack-podcast-player__track-link jetpack-podcast-player__link"
		href="<?php echo esc_url( $track_link ); ?>"
		role="button"
		<?php echo $template_props['is_active'] ? 'aria-current="track"' : ''; ?>
	>
		<span class="jetpack-podcast-player__track-status-icon"></span>
		<span class="jetpack-podcast-player__track-title"><?php echo esc_html( $track_title ); ?></span>
		<time class="jetpack-podcast-player__track-duration"><?php echo esc_html( $track_duration ); ?></time>
	</a>
</li>
