<?php
/**
 * Rectangular layout Tiled Gallery template.
 *
 * @package automattic/jetpack
 */

foreach ( $context['rows'] as $row ) : // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
	?>
	<div
		class="gallery-row"
		style="width: <?php echo esc_attr( $row->width ); ?>px; height: <?php echo esc_attr( $row->height ); ?>px;"
		data-original-width="<?php echo esc_attr( $row->width ); ?>"
		data-original-height="<?php echo esc_attr( $row->height ); ?>"

	>
	<?php foreach ( $row->groups as $group ) : ?>
		<div
			class="gallery-group images-<?php echo esc_attr( count( $group->images ) ); ?>"
			style="width: <?php echo esc_attr( $group->width ); ?>px; height: <?php echo esc_attr( $group->height ); ?>px;"
			data-original-width="<?php echo esc_attr( $group->width ); ?>"
			data-original-height="<?php echo esc_attr( $group->height ); ?>"
		>
			<?php
			foreach ( $group->items( $context['needs_attachment_link'], $context['grayscale'] ) as $item ) : // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
				$this->partial( // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
					'item',
					array(
						'item' => $item,
						'link' => $context['link'], // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
					)
				);
				?>
			<?php endforeach; ?>
		</div> <!-- close group -->
	<?php endforeach; ?>
	</div> <!-- close row -->
<?php endforeach; ?>
