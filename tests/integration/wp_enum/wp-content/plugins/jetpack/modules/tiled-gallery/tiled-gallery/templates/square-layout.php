<?php
/**
 * Square layout Tiled Gallery template.
 *
 * @package automattic/jetpack
 */

foreach ( $context['rows'] as $row ) : // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
	?>
	<div class="gallery-row"
		style="width: <?php echo esc_attr( $row->width ); ?>px; height: <?php echo esc_attr( $row->height ); ?>px;"
		data-original-width="<?php echo esc_attr( $row->width ); ?>"
		data-original-height="<?php echo esc_attr( $row->height ); ?>"
	>
		<?php foreach ( $row->images as $item ) : ?>
			<div class="gallery-group"
				style="width: <?php echo esc_attr( $row->group_size ); ?>px; height: <?php echo esc_attr( $row->group_size ); ?>px;"
				data-original-width="<?php echo esc_attr( $row->group_size ); ?>"
				data-original-height="<?php echo esc_attr( $row->group_size ); ?>"
			>
				<?php
				$this->partial( // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
					'item',
					array(
						'item' => $item,
						'link' => $context['link'], // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
					)
				);
				?>
			</div>
		<?php endforeach; ?>
	</div>
<?php endforeach; ?>
